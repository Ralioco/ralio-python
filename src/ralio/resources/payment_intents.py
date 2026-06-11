"""Payment intents resource — read agent-created payment requests.

Requires the ``transactions:read`` scope (same as :mod:`transactions`).
"""

from __future__ import annotations

from typing import Any

from ..transport import Transport
from ..types import Page, PaymentIntent


class PaymentIntentsResource:
    def __init__(self, transport: Transport) -> None:
        self._transport = transport

    def list(
        self,
        *,
        agent_id: str | None = None,
        page: int = 1,
        per_page: int = 50,
    ) -> Page[PaymentIntent]:
        """List payment intents across the caller's agents, newest first.

        Returns one :class:`~ralio.Page` (``.data`` plus ``.total`` / ``.page``
        / ``.per_page``); pass ``page`` to walk through further pages.
        """
        params: dict[str, Any] = {"page": page, "per_page": per_page}
        if agent_id is not None:
            params["agent_id"] = agent_id
        response = self._transport.request("GET", "/api/payment-intents", params=params)
        return Page._from_api(response.json(), key="payment_intents", item=PaymentIntent._from_api)
