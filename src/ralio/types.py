"""Immutable response types returned by the SDK.

Parsing is forgiving: unknown fields the API may add later are ignored, so a
server-side addition never breaks a pinned client.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CredentialBinding:
    """The result of a completed registration. ``client_id`` is the ``cb_…``
    handle used to mint tokens; the private key lives on disk."""

    client_id: str
    scopes: tuple[str, ...]


@dataclass(frozen=True)
class Message:
    id: str
    role: str
    content: str
    created_at: str | None = None

    @classmethod
    def _from_api(cls, data: dict[str, Any]) -> Message:
        return cls(
            id=data.get("id", ""),
            role=data.get("role", ""),
            content=data.get("content", ""),
            created_at=data.get("created_at"),
        )


@dataclass(frozen=True)
class ChatReply:
    """A synchronous ``chat.send`` response."""

    reply: str
    conversation_id: str
    new_messages: tuple[Message, ...] = ()

    @classmethod
    def _from_api(cls, data: dict[str, Any]) -> ChatReply:
        return cls(
            reply=data.get("reply", ""),
            conversation_id=data.get("conversation_id", ""),
            new_messages=tuple(
                Message._from_api(m) for m in data.get("new_messages", []) or []
            ),
        )


@dataclass(frozen=True)
class ChatStreamEvent:
    """One server-sent event from ``chat.stream``.

    ``event`` is the SSE event name (``conversation``, ``tool_started``,
    ``tool_completed``, ``tool_failed``, ``text_delta``, ``reply``, ``error``);
    ``data`` is the decoded JSON payload. ``text`` is a convenience for the
    common ``text_delta`` / ``reply`` case.
    """

    event: str
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def text(self) -> str:
        value = self.data.get("text")
        return value if isinstance(value, str) else ""


@dataclass(frozen=True)
class Transaction:
    id: str
    amount: str
    currency: str
    status: str
    date: str | None = None
    creditor: str | None = None
    debtor: str | None = None
    reference: str | None = None
    payment_intent_id: str | None = None

    @classmethod
    def _from_api(cls, data: dict[str, Any]) -> Transaction:
        return cls(
            id=data.get("id", ""),
            amount=data.get("amount", ""),
            currency=data.get("currency", ""),
            status=data.get("status", ""),
            date=data.get("date"),
            creditor=data.get("creditor"),
            debtor=data.get("debtor"),
            reference=data.get("reference"),
            payment_intent_id=data.get("payment_intent_id"),
        )
