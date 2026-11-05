"""Input schemas for the customer tools.

The models are strict: no type coercion (``"5"`` is not a float, ``true`` is not a
number) and no unknown fields. The same models generate the ``inputSchema`` that
``tools/list`` advertises, so clients and the server agree on the contract.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

# CUST- followed by exactly five upper-case letters or digits.
CUSTOMER_ID_PATTERN = r"^CUST-[A-Z0-9]{5}$"
REASON_MIN_LENGTH = 10
REASON_MAX_LENGTH = 500

CustomerId = Annotated[str, StringConstraints(pattern=CUSTOMER_ID_PATTERN)]
Reason = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=REASON_MIN_LENGTH,
        max_length=REASON_MAX_LENGTH,
    ),
]


class StrictInput(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class GetCustomerRecordInput(StrictInput):
    customer_id: CustomerId = Field(
        description="Customer identifier, formatted CUST-XXXXX (five upper-case letters or digits).",
    )


class TriggerRefundInput(StrictInput):
    customer_id: CustomerId = Field(
        description="Customer identifier, formatted CUST-XXXXX (five upper-case letters or digits).",
    )
    amount: float = Field(
        gt=0,
        allow_inf_nan=False,
        description="Refund amount in USD. Must be a finite number greater than zero.",
    )
    reason: Reason = Field(
        description=(
            f"Why the refund is issued; {REASON_MIN_LENGTH}-{REASON_MAX_LENGTH} characters "
            "after surrounding whitespace is trimmed."
        ),
    )
