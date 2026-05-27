import httpx
import jwt as pyjwt
import pytest
import respx

from ralio.errors import RalioPermissionError, RalioValidationError

BASE_URL = "https://api.ralio.co"


@respx.mock
def test_chat_send_sends_dpop_headers(client, token_response):
    respx.post(f"{BASE_URL}/oauth/token").mock(
        return_value=httpx.Response(200, json=token_response)
    )
    route = respx.post(f"{BASE_URL}/api/chat").mock(
        return_value=httpx.Response(
            200,
            json={
                "reply": "Your balance is GBP 10,000.",
                "conversation_id": "conv-1",
                "new_messages": [
                    {"id": "m1", "role": "user", "content": "balance?", "created_at": "t"},
                    {"id": "m2", "role": "assistant", "content": "10k", "created_at": "t"},
                ],
            },
        )
    )

    reply = client.chat.send(agent_id="a1", message="balance?")

    assert reply.reply.startswith("Your balance")
    assert reply.conversation_id == "conv-1"
    assert len(reply.new_messages) == 2
    assert reply.new_messages[0].role == "user"

    request = route.calls.last.request
    assert request.headers["Authorization"] == "DPoP access-1"
    proof = pyjwt.decode(request.headers["DPoP"], options={"verify_signature": False})
    assert proof["htm"] == "POST"
    assert proof["htu"] == f"{BASE_URL}/api/chat"
    assert "jti" in proof and "ath" in proof


@respx.mock
def test_retries_once_on_401(client, token_response):
    respx.post(f"{BASE_URL}/oauth/token").mock(
        return_value=httpx.Response(200, json=token_response)
    )
    route = respx.post(f"{BASE_URL}/api/chat").mock(
        side_effect=[
            httpx.Response(401, json={"detail": "expired"}),
            httpx.Response(200, json={"reply": "ok", "conversation_id": "c"}),
        ]
    )

    reply = client.chat.send(agent_id="a1", message="hi")

    assert reply.reply == "ok"
    assert route.call_count == 2
    # The retry must carry a fresh proof (distinct jti).
    opts = {"verify_signature": False}
    jti1 = pyjwt.decode(route.calls[0].request.headers["DPoP"], options=opts)["jti"]
    jti2 = pyjwt.decode(route.calls[1].request.headers["DPoP"], options=opts)["jti"]
    assert jti1 != jti2


@respx.mock
def test_transactions_list_parses_and_passes_params(client, token_response):
    respx.post(f"{BASE_URL}/oauth/token").mock(
        return_value=httpx.Response(200, json=token_response)
    )
    route = respx.get(f"{BASE_URL}/api/transactions").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": "txn_1",
                    "amount": "500.00",
                    "currency": "GBP",
                    "status": "submitted",
                    "creditor": "Bob",
                    "date": "2026-04-04T10:05:00Z",
                }
            ],
        )
    )

    txns = client.transactions.list(agent_id="a1", limit=10)

    assert len(txns) == 1
    assert txns[0].id == "txn_1"
    assert txns[0].amount == "500.00"
    assert dict(route.calls.last.request.url.params) == {"limit": "10", "agent_id": "a1"}


@respx.mock
def test_chat_stream_parses_sse(client, token_response):
    respx.post(f"{BASE_URL}/oauth/token").mock(
        return_value=httpx.Response(200, json=token_response)
    )
    sse = (
        "event: conversation\n"
        'data: {"conversation_id": "conv-1"}\n'
        "\n"
        "event: text_delta\n"
        'data: {"text": "Hello "}\n'
        "\n"
        "event: reply\n"
        'data: {"text": "Hello world"}\n'
        "\n"
    )
    respx.post(f"{BASE_URL}/api/chat/stream").mock(
        return_value=httpx.Response(200, content=sse.encode())
    )

    events = list(client.chat.stream(agent_id="a1", message="hi"))

    assert [e.event for e in events] == ["conversation", "text_delta", "reply"]
    assert events[1].text == "Hello "
    assert events[2].text == "Hello world"


@respx.mock
def test_error_mapping(client, token_response):
    respx.post(f"{BASE_URL}/oauth/token").mock(
        return_value=httpx.Response(200, json=token_response)
    )
    respx.post(f"{BASE_URL}/api/chat").mock(
        return_value=httpx.Response(403, json={"detail": "insufficient_scope"})
    )
    with pytest.raises(RalioPermissionError) as exc:
        client.chat.send(agent_id="a1", message="hi")
    assert exc.value.status_code == 403
    assert exc.value.detail == "insufficient_scope"


@respx.mock
def test_validation_error(client, token_response):
    respx.post(f"{BASE_URL}/oauth/token").mock(
        return_value=httpx.Response(200, json=token_response)
    )
    respx.get(f"{BASE_URL}/api/transactions").mock(
        return_value=httpx.Response(422, json={"detail": "bad limit"})
    )
    with pytest.raises(RalioValidationError):
        client.transactions.list(limit=-1)
