import json

import httpx
import jwt as pyjwt
import pytest
import respx

from ralio.errors import RalioConfigError, RalioPermissionError, RalioValidationError

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
            json={
                "transactions": [
                    {
                        "id": "txn_1",
                        "amount": "500.00",
                        "currency": "GBP",
                        "status": "submitted",
                        "creditor": "Bob",
                        "date": "2026-04-04T10:05:00Z",
                    }
                ],
                "total": 42,
                "page": 1,
                "per_page": 10,
            },
        )
    )

    txns = client.transactions.list(agent_id="a1", page=1, per_page=10)

    assert txns.total == 42
    assert txns.page == 1
    assert txns.per_page == 10
    assert len(txns) == 1
    assert txns.data[0].id == "txn_1"
    assert txns.data[0].amount == "500.00"
    # A Page is iterable for convenience.
    assert [t.id for t in txns] == ["txn_1"]
    assert dict(route.calls.last.request.url.params) == {
        "page": "1",
        "per_page": "10",
        "agent_id": "a1",
    }


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
        client.transactions.list(per_page=-1)


@respx.mock
def test_agents_list_parses_the_bound_agent(client, token_response):
    respx.post(f"{BASE_URL}/oauth/token").mock(
        return_value=httpx.Response(200, json=token_response)
    )
    respx.get(f"{BASE_URL}/api/agents").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": "a1",
                    "name": "Payments",
                    "agent_number": 1,
                    "banking_provider": "griffin",
                    "created_at": "t",
                }
            ],
        )
    )

    agents = client.agents.list()

    assert len(agents) == 1
    assert agents[0].id == "a1"
    assert agents[0].name == "Payments"
    assert agents[0].agent_number == 1
    assert agents[0].banking_provider == "griffin"


@respx.mock
def test_chat_send_resolves_bound_agent_when_agent_id_omitted(client, token_response):
    respx.post(f"{BASE_URL}/oauth/token").mock(
        return_value=httpx.Response(200, json=token_response)
    )
    respx.get(f"{BASE_URL}/api/agents").mock(
        return_value=httpx.Response(200, json=[{"id": "bound-agent", "name": "Only"}])
    )
    route = respx.post(f"{BASE_URL}/api/chat").mock(
        return_value=httpx.Response(
            200, json={"reply": "ok", "conversation_id": "c1", "new_messages": []}
        )
    )

    reply = client.chat.send(message="hi")

    assert reply.reply == "ok"
    assert json.loads(route.calls.last.request.content)["agent_id"] == "bound-agent"


@respx.mock
def test_chat_send_caches_resolved_agent(client, token_response):
    respx.post(f"{BASE_URL}/oauth/token").mock(
        return_value=httpx.Response(200, json=token_response)
    )
    agents_route = respx.get(f"{BASE_URL}/api/agents").mock(
        return_value=httpx.Response(200, json=[{"id": "bound-agent", "name": "Only"}])
    )
    respx.post(f"{BASE_URL}/api/chat").mock(
        return_value=httpx.Response(
            200, json={"reply": "ok", "conversation_id": "c1", "new_messages": []}
        )
    )

    client.chat.send(message="one")
    client.chat.send(message="two")

    assert agents_route.call_count == 1


@respx.mock
def test_chat_send_raises_when_multiple_agents(client, token_response):
    respx.post(f"{BASE_URL}/oauth/token").mock(
        return_value=httpx.Response(200, json=token_response)
    )
    respx.get(f"{BASE_URL}/api/agents").mock(
        return_value=httpx.Response(
            200, json=[{"id": "a1", "name": "One"}, {"id": "a2", "name": "Two"}]
        )
    )

    with pytest.raises(RalioConfigError):
        client.chat.send(message="hi")


@respx.mock
def test_payment_intents_list_parses_and_passes_params(client, token_response):
    respx.post(f"{BASE_URL}/oauth/token").mock(
        return_value=httpx.Response(200, json=token_response)
    )
    route = respx.get(f"{BASE_URL}/api/payment-intents").mock(
        return_value=httpx.Response(
            200,
            json={
                "payment_intents": [
                    {
                        "id": "pi_1",
                        "agent_id": "a1",
                        "agent_name": "Payments",
                        "approval_status": "approved_by_user",
                        "execution_status": "completed",
                        "total_amount": "75.00",
                        "currency": "GBP",
                        "instruction_count": 2,
                        "instructions": [
                            {
                                "amount": "30.00",
                                "currency": "GBP",
                                "status": "completed",
                                "creditor_name": "Acme",
                                "transaction_id": "txn_1",
                                "transaction_status": "delivered",
                            },
                            {
                                "amount": "45.00",
                                "currency": "GBP",
                                "status": "failed",
                                "creditor_name": "Beta",
                                "execution_error": "insufficient funds",
                            },
                        ],
                    }
                ],
                "total": 3,
                "page": 2,
                "per_page": 1,
            },
        )
    )

    intents = client.payment_intents.list(agent_id="a1", page=2, per_page=1)

    assert intents.total == 3
    assert intents.page == 2
    assert intents.per_page == 1
    assert len(intents) == 1
    pi = intents.data[0]
    assert pi.id == "pi_1"
    assert pi.approval_status == "approved_by_user"
    assert pi.execution_status == "completed"
    assert pi.total_amount == "75.00"
    assert pi.instruction_count == 2
    assert len(pi.instructions) == 2
    assert pi.instructions[0].creditor_name == "Acme"
    assert pi.instructions[0].transaction_status == "delivered"
    assert pi.instructions[1].status == "failed"
    assert pi.instructions[1].execution_error == "insufficient funds"
    assert dict(route.calls.last.request.url.params) == {
        "page": "2",
        "per_page": "1",
        "agent_id": "a1",
    }
