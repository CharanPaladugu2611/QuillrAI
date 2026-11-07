# AI Field Developer Assessment

Four tasks around MCP servers and LLM/MCP gateways, plus a zero-trust troubleshooting toolkit. Everything is Python 3.11+ and runs locally with no external accounts (providers are mocked).

| # | Task | Package | Start it |
|---|------|---------|----------|
| 1 | MCP server: strict validation, stdio transport | [`task1_mcp_server`](task1_mcp_server) | `python -m task1_mcp_server` |
| 2 | MCP security gateway: JWT roles, tool filtering | [`task2_mcp_gateway`](task2_mcp_gateway) | `python -m task2_mcp_gateway` |
| 3 | LLM gateway streaming guardrail: PII redaction | [`task3_llm_stream_guardrail`](task3_llm_stream_guardrail) | `python -m task3_llm_stream_guardrail` |
| 4 | Rate limiting and model fallback router | [`task4_llm_router`](task4_llm_router) | `python -m task4_llm_router` |
| – | Zero-trust troubleshooting | [`zero_trust`](zero_trust) | `python -m zero_trust diagnose --gateway URL` |

## Setup

```bash
python -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Dependencies are pinned in `requirements.txt` to the versions this was developed and run with (Windows 11, Python 3.14). In PowerShell, set environment variables with `$env:NAME = "value"` instead of `export NAME=value`.

## Task 1: MCP server with strict validation over stdio

`python -m task1_mcp_server` serves two tools through the official `mcp` SDK (low-level `Server`):

* `get_customer_record(customer_id)`
* `trigger_refund(customer_id, amount, reason)`

To use it from an MCP client:

```json
{ "mcpServers": { "customer-ops": { "command": "python", "args": ["-m", "task1_mcp_server"], "cwd": "<path to this repo>" } } }
```

**Validation** ([`models.py`](task1_mcp_server/models.py)) is Pydantic in strict mode with unknown fields forbidden, and the same models generate the `inputSchema` clients see.

| Field | Rule |
|-------|------|
| `customer_id` | exactly `CUST-` + 5 upper-case letters or digits; trailing newline, whitespace, lower case, Unicode look-alikes and non-strings are rejected |
| `amount` | finite number greater than 0; `0`, negatives, `NaN`, `±Infinity`, `true`, and `"5"` are rejected |
| `reason` | string, at least 10 characters after trimming surrounding whitespace (500 maximum) |

**Error mapping** ([`server.py`](task1_mcp_server/server.py)). Bad input is a JSON-RPC protocol error, raised before any tool code runs; a business failure on well-formed input is a normal result with `isError: true`, so a model can read it and react.

| Situation | Response |
|-----------|----------|
| invalid or missing arguments, non-object `arguments`, unknown tool | `-32602 Invalid params`, with per-field `data.errors` (rejected values are not echoed back) |
| unknown method | `-32601 Method not found` |
| input that is not JSON | `-32700 Parse error` (`id: null`) |
| JSON that is not a JSON-RPC request | `-32600 Invalid Request` (`id: null`) |
| unexpected exception in a tool | `-32603 Internal error`; details only in the stderr log |
| unknown customer, refund below one cent | result with `isError: true` |

**stdout carries JSON-RPC frames and nothing else.**

* Logging is bound to stderr before anything else runs.
* The source contains no `print` and never touches `sys.stdout`.
* While serving, the SDK's stdio transport points file descriptor 1 at stderr, so even `print`, a direct `os.write(1, ...)` or a chatty child process cannot reach the protocol stream.
* [`transport.py`](task1_mcp_server/transport.py) closes two gaps in the stock transport: an unreadable line now gets a `-32700`/`-32600` reply instead of being dropped, and responses to in-flight requests are no longer lost when stdin closes early (`cat requests.jsonl | python -m task1_mcp_server` works).

## Task 2: MCP security gateway

An HTTP reverse proxy (FastAPI + httpx) in front of a downstream MCP server.

```bash
export GATEWAY_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export DOWNSTREAM_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python -m task2_mcp_gateway.mock_downstream &     # downstream on :9000, requires DOWNSTREAM_TOKEN
python -m task2_mcp_gateway &                     # gateway on :8080

TOKEN=$(python -m task2_mcp_gateway.mint_token --role viewer)
curl -s localhost:8080/mcp -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"admin_reset_key"}}'
# {"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Unauthorized Tool Call"}}
```

* **Authentication.** `Authorization: Bearer <JWT>`, HS256 only; `exp` and `sub` are required and the role comes from the `role` claim (`admin` or `viewer`). The algorithm list is pinned, so `alg: none` and algorithm-confusion tokens fail. Missing, malformed, expired, mis-signed or future-dated tokens get `401`; a valid token with an unknown role gets `403`. The response never says why (the audit log does). The secret must be at least 32 characters or the gateway refuses to start.
* **`tools/list`** and every other method are forwarded as the original bytes.
* **`tools/call`** with a `params.name` starting `admin_` requires the `admin` role; otherwise the gateway answers `{"error": {"code": -32001, "message": "Unauthorized Tool Call"}}` itself, echoing the request `id`, and the downstream is never contacted.
* **Wire format.** Requests, notifications, responses and batches are handled per JSON-RPC 2.0. Malformed JSON gets `-32700` and a structurally invalid request gets `-32600` (both HTTP 400). Duplicate keys and `NaN` are rejected, which closes parser-differential bypasses (`{"name":"get_time","name":"admin_x"}`). A denied notification is dropped with `202`. In a mixed batch only the forbidden calls are answered locally and the rest are forwarded and merged.
* **Fails closed.** Tool names are compared after NFKC normalisation, trimming and case folding, so `ADMIN_reset_key` and ` admin_reset_key` cannot slip past a downstream that normalises more loosely. A `tools/call` without a string `name` is rejected locally with `-32602`.
* **Credential hygiene.** The caller's bearer token is never forwarded. The gateway authenticates to the downstream with its own credential and passes the verified identity as `X-Authenticated-User` / `X-Authenticated-Role`. Headers are forwarded from an allow-list (no cookies).
* **Failures.** Downstream down or slow gives `502`/`504` with a fixed JSON-RPC error (`-32003`/`-32004`) and no hostnames or exception text. Request bodies are capped (1 MiB).

| HTTP | JSON-RPC code | Meaning |
|------|---------------|---------|
| 401 / 403 | -32000 | missing or invalid token / unrecognised role |
| 200 | -32001 | unauthorized tool call (the specified error) |
| 400 | -32700 / -32600 | parse error / invalid request |
| 413 | -32600 | body too large |
| 502 / 504 | -32003 / -32004 | downstream unavailable / timed out |

## Task 3: Streaming guardrail (PII redaction)

`python -m task3_llm_stream_guardrail` serves `POST /v1/chat/completions` (OpenAI-style SSE). Without `UPSTREAM_URL` it uses a mock provider that streams a PII-laden reply in tiny deltas:

```bash
curl -N localhost:8082/v1/chat/completions -H 'content-type: application/json' \
     -d '{"messages":[{"role":"user","content":"hi"}],"stream":true}'
```

The guardrail is built from **detectors**: small, independent plug-ins that each recognise one kind of identifier. All of them run on every reply, and they match the *value*, never keywords: `jeff at jeff@aloha.com` is redacted whatever words surround the address. A match becomes `[REDACTED]` (only the value, when a label gives it away). Set `UPSTREAM_URL`, `UPSTREAM_API_KEY` and `UPSTREAM_MODEL` to route to a real OpenAI-compatible provider.

| Detector | Catches | Example |
|---|---|---|
| `email` | addresses, Unicode included | `jeff@aloha.com`, `josé@münchen.de` |
| `email_obfuscated` | addresses written to dodge filters | `jeff at aloha dot com`, `jeff[at]aloha.com` |
| `phone` | numbers with a `+` code, brackets or separators | `(415) 555-0199`, `+44 20 7946 0958` |
| `ssn` | US social security numbers | `123-45-6789` |
| `card` | payment cards, Luhn-checked | `4111 1111 1111 1111` |
| `iban` | bank accounts, checksum-checked | `GB82 WEST 1234 5698 7654 32` |
| `ipv4`, `ipv6`, `mac` | network identifiers | `192.168.1.10`, `2001:db8::1`, `00:1A:2B:3C:4D:5E` |
| `api_key`, `jwt`, `url_credentials`, `private_key` | credentials | `AKIA...`, `ghp_...`, `eyJ...`, `postgres://user:pw@host`, PEM blocks |
| `ssn_labelled`, `phone_labelled`, `date_of_birth`, `passport`, `drivers_license`, `bank_account` | values only recognisable by the label before them | `SSN 123456789`, `passport no. X1234567`, `born on 3 May 1990`, `account number 12345678` |
| `credential`, `stated_password`, `bearer_token` | secrets after a label | `password=hunter2`, `my password is hunter2`, `Bearer ...` |

**Names, addresses and other free text.** No pattern can tell a person's name from any other capitalised word, so the guardrail does not guess: "my name is Jeff Smith" passes unless you tell it about Jeff. Three opt-in routes cover it:

* a **word list** of names you know (customers, staff, code names), matched as whole words, case-insensitively;
* your own **patterns** and **labelled values** (`EMP-123456`, `member id: AB12CD34`);
* a **model**: wrap any function that returns spans, such as an NER model, in `CallableDetector`. It needs whole sentences to judge, so the unfinished sentence is held back; that is the price of context-sensitive detection. No model is bundled, and the hook has only been exercised with a stand-in function.

Point `GUARDRAIL_CONFIG` at a JSON file to choose detectors and add your own. Unknown keys and invalid patterns stop the service from starting, so a typo cannot silently weaken it:

```json
{
  "disable": ["ipv4"],
  "terms": [{"name": "people", "terms": ["Jeff", "Jeff Smith", "Aloha Corp"]}],
  "patterns": [{"name": "employee_id", "regex": "EMP-[0-9]{6}(?![0-9])", "max_length": 10}],
  "labelled": [{"name": "member_id", "labels": ["member id"], "value": "[A-Z0-9]{8}(?![A-Za-z0-9])", "max_value_length": 8}],
  "replacement": "[REDACTED:{label}]"
}
```

`detectors` replaces the default list, `disable` removes names from whatever list is in force, and `{label}` in `replacement` becomes the detector's name (`[REDACTED:email]`).

**Writing a detector.** A detector answers two questions: where are the matches (`spans`), and where might one still be growing (`pending`). The contract is written out in [`detectors/base.py`](task3_llm_stream_guardrail/detectors/base.py), and `verify_contract` checks a detector against it:

```python
from task3_llm_stream_guardrail.app import create_app
from task3_llm_stream_guardrail.detectors import DEFAULT_NAMES, RegexDetector, build, verify_contract
from task3_llm_stream_guardrail.redactor import Engine

order = RegexDetector("order_id", r"ORD-[0-9]{8}(?![0-9])", max_span=12, run=r"\S")
assert verify_contract(order, ["see ORD-12345678 now", "ORD-1234"]) == []
app = create_app(provider, engine=Engine([*build(DEFAULT_NAMES), order]))
```

**How it stays fast and bounded** ([`redactor.py`](task3_llm_stream_guardrail/redactor.py)):

* PII can span chunks (`"john@ex"` + `"ample.com"`, `"jeff at "` + `"aloha dot com"`), so a small tail has to be held back. Each detector reports where a match could still be growing and the redactor holds the text from the earliest such point; everything before it is final and released immediately. In ordinary prose only the last word is held, so the cost is about one token of latency.
* The release point never falls inside a match that is already complete, and detectors see a few characters of text that was already released, so look-behind rules and labels such as `passport` behave exactly as they would on the whole text. That is what makes streamed output identical to redacting the whole text at once, whatever the chunk boundaries.
* Memory does not depend on response length. No detector holds more than its `max_span`, so the engine holds at most a few KB (an unfinished PEM private key block is the largest, at 8 KB). A detector only holds a long token when it starts like one of its matches, so very long ordinary tokens (base64 blobs, minified code) cost almost nothing.
* Regexes are compiled once, detectors skip text that cannot contain their trigger, and bytes are buffered until an SSE event is complete, so a multi-byte character split across network reads cannot corrupt a delta.
* The held tail is released before the event carrying `finish_reason` or `[DONE]`, so nothing is lost and ordering is preserved. A field that stops early, such as reasoning followed by the answer, therefore has its last word released when the choice finishes.
* Every field that carries generated text has its own redactor per choice: `content`, `refusal`, `reasoning_content` and `reasoning`, the legacy `text`, each tool call's `arguments` and the legacy `function_call.arguments`. PII split across events is protected in all of them, and text in one field is never joined to text in another.
* `logprobs` is replaced by `null`. A value spans several tokens, and the token strings and their bytes would repeat exactly what was redacted.
* Events that carry nothing to change are forwarded as the original bytes.
* Upstream failure before any output returns a clean `502`. A failure mid-stream delivers the (redacted) text already received, then a sanitised error event and `[DONE]`. A client disconnect closes the upstream call.

Measured with `python -m task3_llm_stream_guardrail.bench` (mock provider, loopback, Windows dev machine; the 20 ms delta delay becomes about 31 ms because of Windows' 15.6 ms timer granularity):

| | first text | complete |
|---|---|---|
| guarded | 60.8 ms | 3406.5 ms |
| pass-through | 30.3 ms | 3404.7 ms |

The extra ~30 ms before the first text is one delta: the last word is always held until the next arrives, so a disguised address such as `jeff at aloha dot com` can be recognised across chunks; the rest of the stream runs at the provider's pace (+1.8 ms over the whole reply; run-to-run variation is a few milliseconds). With all 22 detectors the redactor costs about 37 µs of CPU per 6-character fragment (roughly 0.2% of one core per stream at 50 tokens/s) and redacts about 3.2 MB/s when given a whole text in one call; over a 0.5 MB stream the peak traced memory was 11 KiB with at most 21 characters held.

Detection limits are explicit: e-mail local parts are at most 64 characters, domains have at most eight 63-character labels plus a 24-character TLD (601 characters total), payment cards have at most 19 digits, and every other detector documents its `max_span`. Values outside the limits are not suffix-matched as PII. The heuristic detectors (labelled values, disguised addresses, phone numbers) can miss unusual formats and occasionally redact something harmless, such as a part number that looks like a phone number; any detector can be switched off by name in the config. **No filter can promise that every identifier is found.** A value the model splits up itself (`four one one one...`), spells out in words or encodes is not recognised, and names and addresses need a word list or a model as described above. Text is inspected only where it is a plain string in the fields above. Audio transcripts, `content` sent as an array of parts and other provider-specific fields (citations, `thinking`) are forwarded unchanged; [the assumptions](#assumptions-and-how-production-would-differ) say what to do about them.

## Task 4: Rate limiting and model fallback router

`python -m task4_llm_router` serves `POST /v1/chat/completions` with a tenant API key (`Authorization: Bearer <key>` or `X-API-Key`). Configure the accepted keys before startup:

```bash
export GATEWAY_API_KEYS="tenant-key-1,tenant-key-2"
python -m task4_llm_router
```

PowerShell: `$env:GATEWAY_API_KEYS = "tenant-key-1,tenant-key-2"`. If the allow-list is absent, startup fails closed with exit code 2. A local mock demo can deliberately accept any non-empty key by setting `ALLOW_UNCONFIGURED_API_KEYS=1`; that mode is unsafe for shared or production environments and is never enabled implicitly.

Without `PRIMARY_URL` the service runs two mock providers; `DEMO_PRIMARY=rate_limited` or `slow` makes the primary misbehave so the failover is visible (`"gateway": {"served_by": "fallback"}`). Real providers: `PRIMARY_URL`/`PRIMARY_API_KEY`/`PRIMARY_MODEL` and the `BACKUP_*` equivalents.

**Rate limiter** ([`limiter.py`](task4_llm_router/limiter.py)): 50,000 tokens per rolling 60 s per tenant, kept in an **on-disk SQLite** file (`RATE_LIMIT_DB`, WAL mode).

* Each admitted request is a row `(tenant, ts_ms, tokens)`; usage is the sum of rows younger than the window, so the window slides continuously (a row expires exactly `window` after it was written).
* Admission is one `BEGIN IMMEDIATE` transaction (evict expired rows, sum, compare, insert), so check-and-reserve is atomic across threads, connections and processes.
* A request first reserves its worst case (prompt estimate + `max_tokens`) and is then settled to the provider's reported usage. If nothing was consumed the reservation is released. If the caller disconnects mid-flight the reservation is kept, because an upstream call may already be billed.
* A denial carries an exact `Retry-After`: the moment enough old usage will have expired. A request larger than the whole allowance gets `413` since waiting can never help.
* Expired rows are evicted per tenant on every reservation and globally every 30 s. API keys are stored only as SHA-256 hashes.

**Router** ([`router.py`](task4_llm_router/router.py)): the primary gets 3000 ms (`asyncio.timeout`); on a **429** or a **timeout** the request goes to the backup. The slow call is cancelled, so a late reply can never be served twice. Connection errors and 5xx fail over only when `FAILOVER_ON_SERVER_ERRORS=1`; the requirement names 429 and timeout, so other failures are reported rather than retried.

**Errors** ([`errors.py`](task4_llm_router/errors.py)). Every error body is `{"error": {"code", "message", "request_id"}}` built from a fixed catalogue. Upstream bodies, hostnames and exception text never reach the client.

| Code | HTTP |
|------|------|
| `unauthorized` | 401 |
| `invalid_request` | 400 |
| `request_too_large` | 413 |
| `rate_limit_exceeded` (+ `Retry-After`) | 429 |
| `upstream_error` | 502 |
| `upstream_unavailable` (all providers tried) | 503 |
| `internal_error` | 500 |

## Zero-trust troubleshooting

The assessment overview lists "troubleshooting zero-trust network deployments" as a focus area, but none of the four tasks specifies it. Since it is in the heading, I treated it as in scope and added [`zero_trust`](zero_trust), a diagnostic toolkit for the Task 2 gateway deployment.

```bash
export GATEWAY_JWT_SECRET=...  DOWNSTREAM_TOKEN=...      # read from the environment, never the command line
python -m zero_trust diagnose --gateway https://gw.internal --downstream https://mcp.internal
python -m zero_trust diagnose --gateway https://gw.internal --ca-bundle ca.pem --client-cert c.pem --client-key k.pem --json
python -m zero_trust token "$JWT" --secret-env GATEWAY_JWT_SECRET
```

`diagnose` probes from outside, exits non-zero on any failure, and attaches a fix to each one. The probes are read-only (`tools/list`, plus a call to a tool that does not exist), so they are safe against a live deployment.

* **Network and transport.** Reachability, with failures classified as DNS, connection refused, silent drop (timeout), reset, expired or untrusted certificate, hostname mismatch, or a missing client certificate (mTLS). TLS version and certificate expiry. Plaintext HTTP off loopback is flagged. Clock skew against the gateway's `Date` header.
* **Authentication.** Missing, malformed, wrong-key, `alg=none` and expired tokens must all be rejected. A valid token must be accepted; if it is not, the tool tells a secret mismatch (with a fingerprint, never the secret) from a gateway clock running behind.
* **Authorization.** A viewer must be denied `admin_*` tools, including case and whitespace variants. An admin must get through.
* **Disclosure.** Malformed requests must not produce stack traces, source paths, private addresses or connection strings.
* **Downstream isolation.** The downstream must refuse anonymous callers, a presented end-user JWT, and spoofed `X-Authenticated-*` headers (otherwise it is trusting network position), and must accept the gateway's own credential. An unreachable downstream is reported as segmentation working.

`token` explains whether a bearer token will be accepted (algorithm, role, expiry, clock skew, signature) without trusting its contents.

Healthy deployment:

```
  PASS  gateway.reachable                      HTTP 200 from http://127.0.0.1:PORT
  PASS  auth.alg-none                          an unsigned (alg=none) token rejected with HTTP 401
  PASS  authz.viewer-blocked-from-admin-tools  denied at the gateway with -32001 Unauthorized Tool Call
  PASS  downstream.no-anonymous-access         an anonymous request to the downstream rejected with HTTP 401
  ...
17 passed, 0 warnings, 0 failed, 0 skipped
```

A gateway with an oversized `JWT_LEEWAY_S` and a downstream that trusts the network:

```
  FAIL  auth.expired-token                     a correctly signed but expired token was ACCEPTED (HTTP 200)
        fix: Expiry is not enforced: check JWT_LEEWAY_S (a large leeway makes old tokens live on) and that exp is required.
  FAIL  downstream.no-anonymous-access         the downstream answered an unauthenticated request (HTTP 200)
        fix: The downstream trusts network position. Require a credential from the gateway (mTLS or a service token) ...
```

## Assumptions and how production would differ

The brief leaves some details open, and everything here runs against mocks so that no network access or credentials are needed. This section lists every assumption I made, what the code does about it, and how a live deployment would differ. Items marked **gap** are limitations that anyone relying on this code should know about.

### Reading the brief

| Assumption | Here | In production |
|---|---|---|
| Zero-trust troubleshooting is in scope | It is in the overview heading but no task specifies it, so I built [`zero_trust`](zero_trust) as a diagnostic CLI for the Task 2 deployment. | Probes see a deployment from one vantage point. They cannot see mesh authorisation policy, firewall rules, device posture or workload identity, so they complement config audits and flow logs rather than replace them. |
| `tools/list` is forwarded untouched | The requirement says to forward it transparently while the task title mentions filtering. I followed the requirement, so a viewer can see the names of admin tools but cannot call them. | Filter the list per role, so a viewer cannot learn which privileged tools exist. |
| Standard JSON-RPC error codes | Bad input is `-32602`, unknown tools included (the MCP specification's example), because `-32601` is for unknown methods. Gateway-specific codes are in the `-32000` range. | No difference expected. The gateway codes would be published as part of the API contract. |

### Task 1: MCP server

| Assumption | Here | In production |
|---|---|---|
| Customer id format | `CUST-` plus five upper-case letters or digits. The brief only says `CUST-XXXXX`; the pattern is one constant in [`models.py`](task1_mcp_server/models.py). | The format comes from the system of record. Keep the pattern as a cheap first check, align it with the real format, and let the backend decide whether the customer exists. |
| Customer data | Four seeded customers held in memory. The record returns name and email as stored. | A CRM or billing service behind an API, with the fields returned limited to what the caller is allowed to see. |
| Refunds | An in-memory list that disappears on exit. Amounts are floats rounded to cents, in USD. Nothing stops the same refund being issued twice, a suspended customer being refunded, or a refund larger than the original payment. | Integer minor units or `Decimal` with a currency, an idempotency key on every request, checks against the original payment and earlier refunds, approval thresholds, a durable audit trail, and the payment processor's API behind it. |
| Authentication | None. A stdio server trusts whichever process launched it. | A remote MCP server needs real authentication (OAuth 2.1 under the MCP authorization specification). Task 2 stands in for that with a JWT. |

### Task 2: MCP gateway

| Assumption | Here | In production |
|---|---|---|
| Bearer token | HS256 JWT signed with a shared secret of at least 32 characters from the environment. The role comes from the `role` claim (`admin` or `viewer`); `iss` and `aud` are checked only if configured. | Tokens issued by an identity provider (OIDC), signed asymmetrically and verified against its published keys with rotation (`kid`), with `iss` and `aud` always required, short lifetimes and a revocation story. Roles come from IdP groups or a policy engine. The secret lives in a secrets manager. |
| Authorisation rule | A `tools/call` whose name starts with `admin_` needs the `admin` role; everything else is allowed for any valid role. | An explicit per-tool policy (an allow-list by role or scope) enforced at the gateway, with the downstream enforcing its own checks too. A naming prefix is a convention, not a security boundary. |
| Gateway to downstream | The gateway's own static bearer token (`DOWNSTREAM_TOKEN`), plus the verified identity in `X-Authenticated-User` and `X-Authenticated-Role`. | mTLS or workload identity with short-lived credentials. The downstream accepts identity headers only from the gateway (network policy), ideally as a signed assertion rather than plain headers. |
| MCP sessions | `Mcp-Session-Id` is forwarded as received. **Gap:** the gateway does not tie a session to the caller who opened it. | Bind each session to the authenticated principal and reject any other caller presenting it. |
| Transport and scale | Plain HTTP on `127.0.0.1`, one process, a 1 MiB body cap, a 30 s downstream timeout and no per-caller rate limit. | TLS at the ingress or mutual TLS in a mesh, several replicas, per-caller quotas, and limits tuned from real traffic. |
| Audit trail | Log lines on stderr with request id, principal, decision and tool. Tokens are never logged. | Structured logs shipped to a SIEM with retention, and alerts on repeated denials or authentication failures. |

### Task 3: streaming guardrail

| Assumption | Here | In production |
|---|---|---|
| Provider format | OpenAI-style chat-completion SSE (`choices[].delta`), served by a mock provider by default. The HTTP adapter has not been run against a live provider. | Other vendors stream different event shapes, so each needs an adapter that maps its events onto the fields the guard protects. |
| Fields that are redacted | `content`, `refusal`, `reasoning_content`, `reasoning`, the legacy `text`, tool-call `arguments` and the legacy `function_call.arguments`, each as its own stream. `logprobs` is replaced by `null`. **Gap:** I tested that audio transcripts, `content` sent as an array of parts, and other provider-specific fields such as citations or `thinking` are forwarded unchanged. | Cover every text-bearing field the chosen provider can emit. A plain string field is added by naming it in `TEXT_FIELDS` ([`guardrail.py`](task3_llm_stream_guardrail/guardrail.py)); shapes that cannot be redacted in flight, such as audio, should be switched off at the provider. |
| Direction | Only the model's reply is scanned. | Also scan prompts before they leave your boundary, and keep PII out of your own logs. |
| What counts as PII | Pattern, checksum and label based detectors for common US and European formats, plus optional word lists. Names and addresses are not detected on their own. Heuristics can miss unusual formats and occasionally redact harmless text. | Layered detection: locale-specific rules plus a trained entity recogniser, measured on labelled data for precision and recall, with the definition of PII agreed with compliance (GDPR, HIPAA, PCI) and redaction rates monitored. |
| Access control | None; the endpoint is open. | Behind an authenticated gateway with per-tenant limits, such as Task 4's, in front. |
| Latency and CPU | The last word is held back, which added about 30 ms before the first text in the benchmark, and the redactor costs about 37 µs of CPU per fragment in one Python process. | The delay is one gap between tokens at the provider's real cadence. Measure under concurrent load: one process shares its CPU across every stream, so scale out, or move the hot path to a faster runtime if profiling says so. |
| Benchmark conditions | Mock provider, loopback, Windows (15.6 ms timer granularity). | Real network, TLS and token cadence; the numbers will differ. |

### Task 4: rate limiter and router

| Assumption | Here | In production |
|---|---|---|
| Tenant | Each API key is its own tenant (keys are hashed) with its own 50,000-token budget. Keys come from a comma-separated environment variable, so changing them needs a restart. | The tenant is the customer or organisation from the authenticated identity, so several keys can share one budget. Keys live in a secrets store or database with rotation and per-key metadata. |
| What is counted | Prompt plus completion tokens against 50,000 per rolling minute. A request reserves a `characters / 4` estimate plus `max_tokens` (1024 when absent), then is settled to the provider's reported usage. | A tokenizer that matches the model, or the provider's token-count API; four characters per token is off for code and non-English text. Whether the budget covers input, output or both should follow the contract and billing. |
| Storage | One SQLite file (WAL, `synchronous=NORMAL`), one row per request. | Correct for one node, or processes sharing a local disk. Several replicas need a shared store such as Redis or Postgres, because SQLite on a network filesystem is unsafe. At high request rates, aggregate into time buckets to cap the row count. An operating-system crash or power loss can lose the most recent writes under `NORMAL`, which allows brief over-admission. |
| Clock | The system clock (`time.time`), because the window has to survive restarts. | Time taken from the shared store, so clock steps or skew between nodes cannot stretch or shrink the window. |
| Failover triggers | Only a 429 or a 3000 ms timeout, as specified. Connection errors and 5xx responses are returned as errors unless `FAILOVER_ON_SERVER_ERRORS=1`. | Usually 5xx and connection errors fail over too, behind a circuit breaker so a dead primary stops being tried, with backoff and the primary's `Retry-After` honoured. |
| The 3000 ms bound | Applies per attempt to the whole non-streaming completion, so two providers can take about 6 s in the worst case. Tokens consumed by a cancelled attempt are not charged to the tenant. | For streaming, time to first token is the sensible bound; a 3 s cap on a full answer trips on any long reply. Cancelled attempts are counted conservatively or reconciled against provider billing. |
| Backup model | Treated as a drop-in replacement. Each provider's model is pinned in its configuration, so the client's `model` field is accepted but not forwarded. | Models differ in quality, context length, tokenizer, price and data-handling terms, so failing over to another vendor may need prompt changes and compliance sign-off. A routing table maps requested models to providers. |
| Scope | Non-streaming only, and Tasks 3 and 4 are separate services. | One gateway pipeline: authenticate, limit, route with failover, then guard the stream. |

### Across the project

| Assumption | Here | In production |
|---|---|---|
| Platform | Developed and run on Windows 11 with Python 3.14.3 and the pinned versions. I have not run it on Linux or macOS. | Containers, CI on the target operating system, and dependency scanning. |
| Secrets | Environment variables. | A secrets manager with rotation. |
| Observability | `/healthz` (liveness only) and logs on stderr. | Readiness checks, metrics (latency, denials, failover and redaction rates) and tracing. |
| Error detail | Clients get fixed messages and a request id; details stay in the server log. | The same, with the logs centralised and access-controlled. |

## Layout

```
task1_mcp_server/            MCP server, strict models, stdio transport wrapper
task2_mcp_gateway/           JWT auth, JSON-RPC parsing, policy, proxy, mock downstream
task3_llm_stream_guardrail/  redaction engine, detectors/ (framework + built-ins), config, SSE parser, stream guard, endpoint, benchmark
task4_llm_router/            SQLite limiter, router, providers, endpoint
zero_trust/                  probes, token inspector, network diagnosis, CLI
```
