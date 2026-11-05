"""Token-aware sliding-window rate limiter backed by an on-disk SQLite database.

Every admitted request is a row ``(tenant, ts_ms, tokens)``. A tenant's usage is the
sum of its rows younger than the window, so the window slides continuously instead of
resetting on minute boundaries. Admission is a single ``BEGIN IMMEDIATE`` transaction
(evict, sum, compare, insert), which makes check-and-reserve atomic across threads,
connections and processes sharing the file.

A request first *reserves* its worst-case cost (prompt estimate + ``max_tokens``).
After the upstream call the reservation is *settled* to the provider-reported usage,
or *released* when nothing was consumed.

Time comes from ``time.time`` because the state outlives the process; a monotonic
clock would not be comparable across restarts. The clock is injectable for tests.
"""

from __future__ import annotations

import asyncio
import math
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

DEFAULT_LIMIT_TOKENS = 50_000
DEFAULT_WINDOW_SECONDS = 60.0

_SCHEMA = """
CREATE TABLE IF NOT EXISTS token_usage (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant TEXT    NOT NULL,
    ts_ms  INTEGER NOT NULL,
    tokens INTEGER NOT NULL CHECK (tokens >= 0)
);
CREATE INDEX IF NOT EXISTS idx_token_usage_tenant_ts ON token_usage (tenant, ts_ms);
CREATE INDEX IF NOT EXISTS idx_token_usage_ts ON token_usage (ts_ms);
"""


class RequestTooLarge(Exception):
    """A single request is bigger than the whole window allowance; waiting can never help."""


@dataclass(frozen=True)
class Reservation:
    id: int
    tokens: int
    used_after: int
    limit: int

    @property
    def remaining(self) -> int:
        return max(self.limit - self.used_after, 0)


@dataclass(frozen=True)
class Denied:
    retry_after_s: int
    used: int
    limit: int


class SlidingWindowLimiter:
    def __init__(
        self,
        db_path: str | Path,
        *,
        limit: int = DEFAULT_LIMIT_TOKENS,
        window_s: float = DEFAULT_WINDOW_SECONDS,
        clock: Callable[[], float] = time.time,
        purge_interval_s: float = 30.0,
    ) -> None:
        if limit <= 0 or window_s <= 0:
            raise ValueError("limit and window_s must be positive")
        self.limit = limit
        self.window_ms = int(window_s * 1000)
        self._clock = clock
        self._purge_interval_ms = int(purge_interval_s * 1000)
        self._last_purge_ms = 0
        self._lock = threading.Lock()
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # isolation_level=None: transactions are explicit. One connection, serialised by
        # self._lock; cross-connection and cross-process safety comes from SQLite itself.
        self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=10.0)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA busy_timeout=10000")
        self._db.executescript(_SCHEMA)

    # ------------------------------------------------------------------ sync core

    def _now_ms(self) -> int:
        return int(self._clock() * 1000)

    def reserve_sync(self, tenant: str, tokens: int) -> Reservation | Denied:
        if tokens <= 0:
            raise ValueError("tokens must be positive")
        if tokens > self.limit:
            raise RequestTooLarge
        now_ms = self._now_ms()
        cutoff = now_ms - self.window_ms
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute("DELETE FROM token_usage WHERE tenant = ? AND ts_ms <= ?", (tenant, cutoff))
                if now_ms - self._last_purge_ms >= self._purge_interval_ms:
                    self._db.execute("DELETE FROM token_usage WHERE ts_ms <= ?", (cutoff,))
                    self._last_purge_ms = now_ms
                (used,) = self._db.execute(
                    "SELECT COALESCE(SUM(tokens), 0) FROM token_usage WHERE tenant = ?", (tenant,)
                ).fetchone()

                if used + tokens > self.limit:
                    retry_after = self._retry_after_s(tenant, used, tokens, now_ms)
                    self._db.execute("COMMIT")
                    return Denied(retry_after_s=retry_after, used=used, limit=self.limit)

                cursor = self._db.execute(
                    "INSERT INTO token_usage (tenant, ts_ms, tokens) VALUES (?, ?, ?)", (tenant, now_ms, tokens)
                )
                self._db.execute("COMMIT")
                return Reservation(id=cursor.lastrowid, tokens=tokens, used_after=used + tokens, limit=self.limit)
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def _retry_after_s(self, tenant: str, used: int, tokens: int, now_ms: int) -> int:
        """Seconds until enough of the oldest usage expires for ``tokens`` to fit."""
        must_free = used + tokens - self.limit
        freed = 0
        for ts_ms, row_tokens in self._db.execute(
            "SELECT ts_ms, tokens FROM token_usage WHERE tenant = ? ORDER BY ts_ms, id", (tenant,)
        ):
            freed += row_tokens
            if freed >= must_free:
                return max(math.ceil((ts_ms + self.window_ms - now_ms) / 1000), 1)
        return math.ceil(self.window_ms / 1000)  # unreachable while tokens <= limit

    def settle_sync(self, reservation: Reservation, actual_tokens: int) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE token_usage SET tokens = ? WHERE id = ?", (max(int(actual_tokens), 0), reservation.id)
            )

    def release_sync(self, reservation: Reservation) -> None:
        with self._lock:
            self._db.execute("DELETE FROM token_usage WHERE id = ?", (reservation.id,))

    def usage_sync(self, tenant: str) -> int:
        cutoff = self._now_ms() - self.window_ms
        with self._lock:
            (used,) = self._db.execute(
                "SELECT COALESCE(SUM(tokens), 0) FROM token_usage WHERE tenant = ? AND ts_ms > ?", (tenant, cutoff)
            ).fetchone()
        return used

    def row_count_sync(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM token_usage").fetchone()[0]

    def purge_expired_sync(self) -> int:
        cutoff = self._now_ms() - self.window_ms
        with self._lock:
            return self._db.execute("DELETE FROM token_usage WHERE ts_ms <= ?", (cutoff,)).rowcount

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ------------------------------------------------------------------ async API
    # SQLite calls block briefly, so they run on worker threads and never stall the loop.

    async def reserve(self, tenant: str, tokens: int) -> Reservation | Denied:
        return await asyncio.to_thread(self.reserve_sync, tenant, tokens)

    async def settle(self, reservation: Reservation, actual_tokens: int) -> None:
        await asyncio.to_thread(self.settle_sync, reservation, actual_tokens)

    async def release(self, reservation: Reservation) -> None:
        await asyncio.to_thread(self.release_sync, reservation)

    async def usage(self, tenant: str) -> int:
        return await asyncio.to_thread(self.usage_sync, tenant)
