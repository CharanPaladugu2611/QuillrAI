"""Measure the guardrail's cost: ``python -m task3_llm_stream_guardrail.bench``.

Reports redactor throughput, peak memory while streaming several megabytes, and the
time-to-first-text / total-time difference against an identical pass-through gateway.
"""

from __future__ import annotations

import json
import socket
import statistics
import threading
import time
import tracemalloc

import httpx
import uvicorn

from .app import create_app
from .providers import MockChatProvider
from .redactor import HOLD_BOUND, StreamRedactor

PROSE = "The quarterly report shows steady growth across regions, with support costs down 4%. "
PII = "Contact jane.doe@example.com (SSN 123-45-6789) about card 4111 1111 1111 1111. "


def _throughput(megabytes: float = 8.0, fragment: int = 6) -> None:
    text = (PROSE * 20 + PII) * int(megabytes * 1_000_000 / (len(PROSE) * 20 + len(PII)))
    fragments = [text[i : i + fragment] for i in range(0, len(text), fragment)]
    redactor = StreamRedactor()
    tracemalloc.start()
    started = time.perf_counter()
    released = 0
    for part in fragments:
        released += len(redactor.feed(part))
    released += len(redactor.flush())
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(f"redactor   {len(text) / 1e6:.1f} MB in {len(fragments):,} fragments of {fragment} chars")
    print(f"           {len(text) / 1e6 / elapsed:.1f} MB/s, {elapsed / len(fragments) * 1e6:.1f} us/fragment")
    print(f"           peak traced memory {peak / 1024:.0f} KiB, max held {redactor.stats.max_buffered} chars (bound {HOLD_BOUND})")
    print(f"           {redactor.stats.redactions:,} redactions")


class _Server:
    def __init__(self, app) -> None:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self._server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error"))
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def __enter__(self) -> _Server:
        self._thread.start()
        while not self._server.started:
            time.sleep(0.01)
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1/chat/completions"


def _timed_request(client: httpx.Client, url: str) -> tuple[float, float]:
    body = {"messages": [{"role": "user", "content": "hi"}], "stream": True}
    started = time.perf_counter()
    first_text = None
    with client.stream("POST", url, json=body) as response:
        for line in response.iter_lines():
            if first_text is None and line.startswith("data: {"):
                if any(c["delta"].get("content") for c in json.loads(line[6:])["choices"]):
                    first_text = time.perf_counter() - started
    return first_text or 0.0, time.perf_counter() - started


def _latency(delay_s: float = 0.02, runs: int = 15) -> None:
    reply = (PROSE + PII) * 3
    provider = lambda: MockChatProvider(reply=reply, delay_s=delay_s, piece_sizes=(4, 5, 3, 6))
    with _Server(create_app(provider())) as guarded, _Server(create_app(provider(), redact=False)) as plain:
        with httpx.Client(timeout=60) as client:  # one client: TLS context setup is not part of the measurement
            _timed_request(client, guarded.url), _timed_request(client, plain.url)  # warm up
            results = {
                name: [_timed_request(client, server.url) for _ in range(runs)]
                for name, server in (("guarded", guarded), ("pass-through", plain))
            }
    print(f"latency    {len(reply)} chars, one delta every {delay_s * 1000:.0f} ms, {runs} runs each (median)")
    for name, samples in results.items():
        first = statistics.median(s[0] for s in samples) * 1000
        total = statistics.median(s[1] for s in samples) * 1000
        print(f"           {name:<13} first text {first:7.1f} ms   complete {total:8.1f} ms")
    delta_first = statistics.median(s[0] for s in results["guarded"]) - statistics.median(s[0] for s in results["pass-through"])
    delta_total = statistics.median(s[1] for s in results["guarded"]) - statistics.median(s[1] for s in results["pass-through"])
    print(f"           overhead      first text {delta_first * 1000:+7.1f} ms   complete {delta_total * 1000:+8.1f} ms")


def main() -> None:
    _throughput()
    print()
    _latency()


if __name__ == "__main__":
    main()
