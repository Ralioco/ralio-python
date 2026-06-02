"""Agents resource — read the agents this credential can address (read-only)."""

from __future__ import annotations

from ..transport import Transport
from ..types import Agent


class AgentsResource:
    def __init__(self, transport: Transport) -> None:
        self._transport = transport

    def list(self) -> list[Agent]:
        """List the agents the caller can address.

        For a credential binding this is exactly the one agent the binding is
        pinned to — the gateway filters the result to the bound agent. (A human
        JWT caller would see all of its agents, but this SDK is machine-only.)
        """
        response = self._transport.request("GET", "/api/agents")
        return [Agent._from_api(item) for item in response.json()]
