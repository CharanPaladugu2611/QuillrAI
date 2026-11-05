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

Emails, SSNs (`123-45-6789`) and payment cards (13-19 digits, optional single spaces or dashes, **Luhn-validated** so order numbers are not mangled) become `[REDACTED]`. Set `UPSTREAM_URL`, `UPSTREAM_API_KEY` and `UPSTREAM_MODEL` to route to a real OpenAI-compatible provider.

**How it stays fast and bounded** ([`redactor.py`](task3_llm_stream_guardrail/redactor.py)):

* PII can span chunks (`"john@ex"` + `"ample.com"`), so a small tail has to be held back. The redactor holds only what could still grow into a match: the trailing run of e-mail characters, or the trailing run of digits/spaces/dashes from its first digit. Everything before that is final and released immediately. In ordinary prose the held tail is the last word, so the cost is about one token of latency.
* The release point is never allowed to fall *inside* such a run. That is what makes streaming output byte-identical to redacting the whole text at once, whatever the chunk boundaries.
* Memory does not depend on response length. Even delimiter-free input is capped at about 1.2 KB of held text.
* Regexes are compiled once, the digit and e-mail patterns are only run when the text contains a digit or an `@`, and bytes are buffered until an SSE event is complete, so a multi-byte character split across network reads cannot corrupt a delta.
* The held tail is released before the event carrying `finish_reason` or `[DONE]`, so nothing is lost and ordering is preserved. Normal text and every `choices[].delta.tool_calls[].function.arguments` stream have independent redactors, so PII split across tool-argument deltas is protected too. Events that carry no protected fields are forwarded as the original bytes.
* Upstream failure before any output returns a clean `502`. A failure mid-stream delivers the (redacted) text already received, then a sanitised error event and `[DONE]`. A client disconnect closes the upstream call.

Measured with `python -m task3_llm_stream_guardrail.bench` (mock provider, loopback, Windows dev machine; the 20 ms delta delay becomes about 31 ms because of Windows' 15.6 ms timer granularity):

| | first text | complete |
|---|---|---|
| guarded | 29.8 ms | 3403.5 ms |
| pass-through | 29.9 ms | 3403.4 ms |

Redactor throughput was about 4 MB/s on 6-character fragments (1.5 µs per fragment), with 3 KiB peak traced memory over an 8 MB stream and a maximum of 20 characters held.

Detection limits are explicit: e-mail local parts are at most 64 characters, domains have at most eight 63-character labels plus a 24-character TLD (601 characters total); payment cards have at most 19 digits and SSNs are the 11-character dash-separated form. Values outside those limits are not suffix-matched as PII. The streaming buffer remains bounded at about 1.2 KB even for delimiter-free input. Bare nine-digit SSNs remain intentionally unsupported because they are too ambiguous.

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

## Assumptions and decisions

* **Customer id** is `CUST-` plus five **upper-case alphanumeric** characters. The brief only says `CUST-XXXXX`; the pattern is a single constant in [`models.py`](task1_mcp_server/models.py).
* **Bearer token = JWT** (HS256, shared secret) for the gateway.
* **`tools/list` is forwarded untouched.** The task title mentions filtering, but the requirement says to forward it transparently, so I followed the requirement.
* **Error codes** are the standard JSON-RPC ones (see the Task 1 table). Unknown tools use `-32602`, following the MCP specification's example, not `-32601`, which is reserved for unknown methods.
* **Token estimates** use about 4 characters per token behind a single function (`estimate_tokens`), reconciled with the provider's reported usage.
* **Mock providers** are used throughout, so nothing needs network access or credentials. The HTTP provider adapters for real OpenAI-compatible endpoints (Tasks 3 and 4) have not been run against a live provider.
* **Compatibility.** Developed and run on Windows 11 with Python 3.14.3 and the pinned versions. I have not run it on Linux or macOS.

## Layout

```
task1_mcp_server/            MCP server, strict models, stdio transport wrapper
task2_mcp_gateway/           JWT auth, JSON-RPC parsing, policy, proxy, mock downstream
task3_llm_stream_guardrail/  redactor, SSE parser, stream guard, endpoint, benchmark
task4_llm_router/            SQLite limiter, router, providers, endpoint
zero_trust/                  probes, token inspector, network diagnosis, CLI
```
