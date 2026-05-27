"""Official Python SDK for the Ralio agentic payment API."""

from __future__ import annotations

from .client import RalioClient
from .errors import (
    RalioAPIError,
    RalioAuthError,
    RalioConfigError,
    RalioError,
    RalioNotFoundError,
    RalioPermissionError,
    RalioRateLimitError,
    RalioRegistrationError,
    RalioValidationError,
)
from .registration import register
from .types import (
    ChatReply,
    ChatStreamEvent,
    CredentialBinding,
    Message,
    Transaction,
)

__version__ = "0.1.0"

__all__ = [
    "RalioClient",
    "register",
    "ChatReply",
    "ChatStreamEvent",
    "CredentialBinding",
    "Message",
    "Transaction",
    "RalioError",
    "RalioConfigError",
    "RalioRegistrationError",
    "RalioAPIError",
    "RalioAuthError",
    "RalioPermissionError",
    "RalioNotFoundError",
    "RalioValidationError",
    "RalioRateLimitError",
]
