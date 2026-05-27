"""Transactions resource — read executed payments (``transactions:read``)."""

from __future__ import annotations

from typing import Any

from ..transport import Transport
from ..types import Transaction


class TransactionsResource:
    def __init__(self, transport: Transport) -> None:
        self._transport = transport

    def list(
        self,
        *,
        agent_id: str | None = None,
        limit: int = 50,
    ) -> list[Transaction]:
        """List transactions across the caller's agents, newest first."""
        params: dict[str, Any] = {"limit": limit}
        if agent_id is not None:
            params["agent_id"] = agent_id
        response = self._transport.request("GET", "/api/transactions", params=params)
        return [Transaction._from_api(item) for item in response.json()]
