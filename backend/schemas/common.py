"""Generic envelopes shared across routers."""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class Message(BaseModel):
    detail: str


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    total: int = Field(description="Total rows matching the filter, ignoring pagination")
    limit: int
    offset: int

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total
