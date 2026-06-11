"""Immutable response types returned by the SDK.

Parsing is forgiving: unknown fields the API may add later are ignored, so a
server-side addition never breaks a pinned client.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar


@dataclass(frozen=True)
class CredentialBinding:
    """The result of a completed registration. ``client_id`` is the ``cb_…``
    handle used to mint tokens; the private key lives on disk."""

    client_id: str
    scopes: tuple[str, ...]


@dataclass(frozen=True)
class Agent:
    """A payment agent the caller can address."""

    id: str
    name: str
    agent_number: int | None = None
    banking_provider: str | None = None
    created_at: str | None = None

    @classmethod
    def _from_api(cls, data: dict[str, Any]) -> Agent:
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            agent_number=data.get("agent_number"),
            banking_provider=data.get("banking_provider"),
            created_at=data.get("created_at"),
        )


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


@dataclass(frozen=True)
class PaymentInstruction:
    """One payment leg of an intent (payee + the matched transaction's state)."""

    amount: str
    currency: str
    status: str
    idempotency_key: str | None = None
    creditor_account: str | None = None
    creditor_name: str | None = None
    debtor_account: str | None = None
    debtor_name: str | None = None
    reference: str | None = None
    transaction_id: str | None = None
    transaction_status: str | None = None
    execution_error: str | None = None

    @classmethod
    def _from_api(cls, data: dict[str, Any]) -> PaymentInstruction:
        return cls(
            amount=data.get("amount", ""),
            currency=data.get("currency", ""),
            status=data.get("status", ""),
            idempotency_key=data.get("idempotency_key"),
            creditor_account=data.get("creditor_account"),
            creditor_name=data.get("creditor_name"),
            debtor_account=data.get("debtor_account"),
            debtor_name=data.get("debtor_name"),
            reference=data.get("reference"),
            transaction_id=data.get("transaction_id"),
            transaction_status=data.get("transaction_status"),
            execution_error=data.get("execution_error"),
        )


@dataclass(frozen=True)
class PaymentIntent:
    """A payment request created by an agent, with its per-leg breakdown.

    ``approval_status`` and ``execution_status`` are the two status axes; the
    headline ``total_amount``/``currency`` summarise the whole intent.
    """

    id: str
    agent_id: str
    approval_status: str
    execution_status: str
    total_amount: str
    currency: str
    instruction_count: int = 0
    instructions: tuple[PaymentInstruction, ...] = ()
    agent_name: str | None = None
    conversation_id: str | None = None
    created_at: str | None = None
    user_request_summary: str | None = None
    decision_reason: str | None = None
    decided_at: str | None = None
    alignment_outcome: str | None = None

    @classmethod
    def _from_api(cls, data: dict[str, Any]) -> PaymentIntent:
        return cls(
            id=data.get("id", ""),
            agent_id=data.get("agent_id", ""),
            approval_status=data.get("approval_status", ""),
            execution_status=data.get("execution_status", ""),
            total_amount=data.get("total_amount", ""),
            currency=data.get("currency", ""),
            instruction_count=data.get("instruction_count", 0),
            instructions=tuple(
                PaymentInstruction._from_api(i) for i in data.get("instructions", []) or []
            ),
            agent_name=data.get("agent_name"),
            conversation_id=data.get("conversation_id"),
            created_at=data.get("created_at"),
            user_request_summary=data.get("user_request_summary"),
            decision_reason=data.get("decision_reason"),
            decided_at=data.get("decided_at"),
            alignment_outcome=data.get("alignment_outcome"),
        )


T = TypeVar("T")


@dataclass(frozen=True)
class Page(Generic[T]):
    """One page of a list endpoint plus the unpaginated ``total``.

    Iterable and sized for convenience — ``for row in page`` yields the items
    on this page and ``len(page)`` is how many there are, while ``total`` is
    the count across every page.
    """

    data: tuple[T, ...]
    total: int
    page: int
    per_page: int

    def __iter__(self) -> Iterator[T]:
        return iter(self.data)

    def __len__(self) -> int:
        return len(self.data)

    @classmethod
    def _from_api(
        cls,
        payload: dict[str, Any],
        *,
        key: str,
        item: Callable[[dict[str, Any]], T],
    ) -> Page[T]:
        rows = payload.get(key) or []
        return Page(
            data=tuple(item(row) for row in rows),
            total=int(payload.get("total", len(rows))),
            page=int(payload.get("page", 1)),
            per_page=int(payload.get("per_page", len(rows))),
        )
