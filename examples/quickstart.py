"""End-to-end example: register once, then chat and read transactions.

Run the registration step on the host where the agent will live, after the
owner mints a ticket in the console (Settings -> Credentials -> New credential).
"""

import os

import ralio

KEY_PATH = "ralio-key.pem"
AGENT_ID = os.environ["RALIO_AGENT_ID"]


def register_once() -> str:
    """Run this once. Blocks until the owner approves in the console."""
    binding = ralio.register(
        ticket=os.environ["RALIO_TICKET"],
        private_key_path=KEY_PATH,
        requested_scopes=["agents:execute", "transactions:read"],
    )
    print("client_id:", binding.client_id)  # persist this
    return binding.client_id


def main() -> None:
    client = ralio.RalioClient(
        client_id=os.environ["RALIO_CLIENT_ID"],
        private_key_path=KEY_PATH,
    )

    reply = client.chat.send(agent_id=AGENT_ID, message="What is my current balance?")
    print("reply:", reply.reply)

    print("--- streaming ---")
    for event in client.chat.stream(agent_id=AGENT_ID, message="List my recent payments"):
        if event.event == "text_delta":
            print(event.text, end="", flush=True)
        elif event.event == "tool_started":
            print(f"\n[tool] {event.data.get('tool_name')}")
    print()

    for txn in client.transactions.list(limit=10):
        print(f"{txn.date}  {txn.amount} {txn.currency}  -> {txn.creditor}  ({txn.status})")

    client.close()


if __name__ == "__main__":
    main()
