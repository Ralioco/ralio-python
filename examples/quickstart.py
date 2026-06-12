"""End-to-end example: register once, then chat and read transactions.

Run the registration step on the host where the agent will live, after the
owner mints a ticket in the console (Settings -> Credentials -> New credential)
and you export it as RALIO_REGISTRATION_TICKET:

    RALIO_REGISTRATION_TICKET=ralio-reg-... python examples/quickstart.py register
    python examples/quickstart.py
"""

import sys

import ralio


def register_once() -> None:
    """Run this once. The binding is active as soon as the call returns (the
    owner consented by minting the ticket and gets an email receipt with a
    revoke link); the credentials are persisted to ~/.ralio/ so the client
    needs no arguments."""
    binding = ralio.register()  # ticket from RALIO_REGISTRATION_TICKET
    print("registered:", binding.client_id, "key at", binding.key_path)


def main() -> None:
    # Zero-config: reads the persisted credentials. agent_id is resolved
    # automatically for a single-agent credential.
    with ralio.RalioClient() as client:
        reply = client.chat.send(message="What is my current balance?")
        print("reply:", reply.reply)

        print("--- streaming ---")
        for event in client.chat.stream(message="List my recent payments"):
            if event.event == "text_delta":
                print(event.text, end="", flush=True)
            elif event.event == "tool_started":
                print(f"\n[tool] {event.data.get('tool_name')}")
        print()

        page = client.transactions.list(per_page=10)
        print(f"{len(page)} of {page.total} transactions")
        for txn in page:
            print(f"{txn.date}  {txn.amount} {txn.currency}  -> {txn.creditor}  ({txn.status})")


if __name__ == "__main__":
    register_once() if sys.argv[1:] == ["register"] else main()
