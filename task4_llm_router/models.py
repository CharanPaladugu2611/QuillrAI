"""Request and response shapes for the completion endpoint."""

from __future__ import annotations

import math
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

DEFAULT_MAX_TOKENS = 1024
MAX_ALLOWED_TOKENS = 32_768
CHARS_PER_TOKEN = 4  # rough heuristic; replace with a real tokenizer behind estimate_tokens if needed


class Message(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["system", "user", "assistant"]
    content: Annotated[str, StringConstraints(max_length=200_000)]


class CompletionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: str | None = Field(default=None, max_length=128)
    messages: list[Message] = Field(min_length=1, max_length=256)
    max_tokens: int | None = Field(default=None, ge=1, le=MAX_ALLOWED_TOKENS)
    temperature: float | None = Field(default=None, ge=0, le=2)

    @property
    def output_budget(self) -> int:
        return self.max_tokens or DEFAULT_MAX_TOKENS


class Usage(BaseModel):
    prompt_tokens: int
    completion_tokens: int

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


def estimate_tokens(text: str) -> int:
    return math.ceil(len(text) / CHARS_PER_TOKEN) if text else 0


def estimate_prompt_tokens(request: CompletionRequest) -> int:
    # +4 per message approximates role/formatting overhead.
    return sum(estimate_tokens(m.content) + 4 for m in request.messages)
