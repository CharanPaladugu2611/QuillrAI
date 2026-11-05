"""In-memory customer store standing in for a real backend."""

from __future__ import annotations

import threading
import uuid
from dataclasses import asdict, dataclass
from typing import Any


class ToolExecutionError(Exception):
    """A business-rule failure; reported as a tool result with ``isError`` set.

    Distinct from protocol errors (bad parameters, unknown tool), which are
    JSON-RPC errors raised before the tool body runs.
    """


@dataclass(frozen=True)
class CustomerRecord:
    customer_id: str
    name: str
    email: str
    tier: str
    status: str


_SEED = (
    CustomerRecord("CUST-10001", "Ada Lovelace", "ada@example.com", "premium", "active"),
    CustomerRecord("CUST-AB123", "Grace Hopper", "grace@example.com", "standard", "active"),
    CustomerRecord("CUST-00042", "Alan Turing", "alan@example.com", "standard", "active"),
    CustomerRecord("CUST-X9Y8Z", "Edsger Dijkstra", "edsger@example.com", "basic", "suspended"),
)


class CustomerStore:
    def __init__(self, customers: tuple[CustomerRecord, ...] = _SEED) -> None:
        self._customers = {c.customer_id: c for c in customers}
        self._refunds: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def get(self, customer_id: str) -> dict[str, Any]:
        customer = self._customers.get(customer_id)
        if customer is None:
            raise ToolExecutionError(f"No customer found with id {customer_id}")
        return asdict(customer)

    def refund(self, customer_id: str, amount: float, reason: str) -> dict[str, Any]:
        if customer_id not in self._customers:
            raise ToolExecutionError(f"No customer found with id {customer_id}")
        cents_amount = round(amount, 2)
        if cents_amount <= 0:
            raise ToolExecutionError("Amount is below the smallest refundable unit (0.01)")
        receipt = {
            "refund_id": f"RF-{uuid.uuid4().hex[:12].upper()}",
            "customer_id": customer_id,
            "amount": cents_amount,
            "currency": "USD",
            "reason": reason,
            "status": "processed",
        }
        with self._lock:
            self._refunds.append(receipt)
        return receipt

    @property
    def refunds(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._refunds)
