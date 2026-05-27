"""Chat resource — drive an agent with natural language (``agents:execute``)."""

from __future__ import annotations

from collections.abc import Iterator

from ..transport import Transport
from ..types import ChatReply, ChatStreamEvent


class ChatResource:
    def __init__(self, transport: Transport) -> None:
        self._transport = transport

    def send(
        self,
        *,
        agent_id: str,
        message: str,
        conversation_id: str | None = None,
    ) -> ChatReply:
        """Send a message and wait for the agent's complete reply.

        Times out server-side after 120s. For interactive approval flows where
        a human may take longer, use :meth:`stream` instead.
        """
        body = {"agent_id": agent_id, "message": message}
        if conversation_id is not None:
            body["conversation_id"] = conversation_id
        response = self._transport.request("POST", "/api/chat", json_body=body)
        return ChatReply._from_api(response.json())

    def stream(
        self,
        *,
        agent_id: str,
        message: str,
        conversation_id: str | None = None,
    ) -> Iterator[ChatStreamEvent]:
        """Stream the agent's reply as server-sent events.

        Yields ``conversation``, ``tool_started``/``tool_completed``/
        ``tool_failed``, ``text_delta``, and a final ``reply`` event.
        """
        body = {"agent_id": agent_id, "message": message}
        if conversation_id is not None:
            body["conversation_id"] = conversation_id
        return self._transport.stream_sse("POST", "/api/chat/stream", json_body=body)
