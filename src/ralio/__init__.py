"""Official Python SDK for the Ralio agentic payment API."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

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

# Single source of truth is the installed package metadata (pyproject.toml).
try:
    __version__ = version("ralio")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+unknown"

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
