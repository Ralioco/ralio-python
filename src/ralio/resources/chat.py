"""Chat resource — drive an agent with natural language (``agents:execute``)."""

from __future__ import annotations

from collections.abc import Iterator

from ..errors import RalioConfigError
from ..transport import Transport
from ..types import ChatReply, ChatStreamEvent
from .agents import AgentsResource


class ChatResource:
    def __init__(self, transport: Transport, agents: AgentsResource) -> None:
        self._transport = transport
        self._agents = agents
        self._cached_agent_id: str | None = None

    def send(
        self,
        *,
        agent_id: str | None = None,
        message: str,
        conversation_id: str | None = None,
    ) -> ChatReply:
        """Send a message and wait for the agent's complete reply.

        ``agent_id`` is optional: when omitted, the SDK resolves the single
        agent this credential is bound to (looked up once via ``agents.list()``
        and cached). Pass it explicitly only if the credential can reach more
        than one agent.

        Times out server-side after 120s. For interactive approval flows where
        a human may take longer, use :meth:`stream` instead.
        """
        body = {"agent_id": self._resolve_agent_id(agent_id), "message": message}
        if conversation_id is not None:
            body["conversation_id"] = conversation_id
        response = self._transport.request("POST", "/api/chat", json_body=body)
        return ChatReply._from_api(response.json())

    def stream(
        self,
        *,
        agent_id: str | None = None,
        message: str,
        conversation_id: str | None = None,
    ) -> Iterator[ChatStreamEvent]:
        """Stream the agent's reply as server-sent events.

        ``agent_id`` is optional — see :meth:`send`.

        Yields ``conversation``, ``tool_started``/``tool_completed``/
        ``tool_failed``, ``text_delta``, and a final ``reply`` event.
        """
        body = {"agent_id": self._resolve_agent_id(agent_id), "message": message}
        if conversation_id is not None:
            body["conversation_id"] = conversation_id
        return self._transport.stream_sse("POST", "/api/chat/stream", json_body=body)

    def _resolve_agent_id(self, explicit: str | None) -> str:
        """Resolve which agent to address: the explicit ``agent_id`` if given,
        else the single agent this credential is bound to (cached after the
        first lookup)."""
        if explicit:
            return explicit
        if self._cached_agent_id is not None:
            return self._cached_agent_id

        agents = self._agents.list()
        if not agents:
            raise RalioConfigError(
                "No agent is bound to this credential; pass agent_id to chat explicitly."
            )
        if len(agents) > 1:
            raise RalioConfigError(
                f"This credential can reach {len(agents)} agents; "
                "pass agent_id to chat explicitly."
            )
        self._cached_agent_id = agents[0].id
        return self._cached_agent_id
