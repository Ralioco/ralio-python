"""Exception hierarchy for the Ralio SDK."""

from __future__ import annotations

import json

import httpx


class RalioError(Exception):
    """Base class for every error raised by the SDK."""


class RalioConfigError(RalioError):
    """Local configuration problem — missing key file, bad arguments."""


class RalioRegistrationError(RalioError):
    """A credential-binding registration failed — the ticket was invalid,
    expired, or already consumed, the public key was unusable, or the
    server's response didn't match the local key."""


class RalioAPIError(RalioError):
    """An error response from the Ralio API.

    Carries the HTTP ``status_code``, the server-supplied ``detail`` string,
    and the ``WWW-Authenticate`` challenge when present (DPoP/OAuth failures
    put the specific reason there).
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        detail: str | None = None,
        www_authenticate: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail
        self.www_authenticate = www_authenticate


class RalioAuthError(RalioAPIError):
    """401 — missing/invalid token, failed client assertion, or rejected proof."""


class RalioPermissionError(RalioAPIError):
    """403 — token lacks the required scope, or the resource isn't owned."""


class RalioNotFoundError(RalioAPIError):
    """404 — resource does not exist."""


class RalioValidationError(RalioAPIError):
    """422 — invalid field values or a business-rule violation."""


class RalioRateLimitError(RalioAPIError):
    """429 — rate limited. Back off and retry."""


_STATUS_MAP: dict[int, type[RalioAPIError]] = {
    401: RalioAuthError,
    403: RalioPermissionError,
    404: RalioNotFoundError,
    422: RalioValidationError,
    429: RalioRateLimitError,
}


def raise_for_response(response: httpx.Response) -> None:
    """Raise the appropriate :class:`RalioAPIError` if *response* is an error."""
    if response.is_success:
        return
    detail = _extract_detail(response)
    cls = _STATUS_MAP.get(response.status_code, RalioAPIError)
    message = detail or f"HTTP {response.status_code}"
    raise cls(
        message,
        status_code=response.status_code,
        detail=detail,
        www_authenticate=response.headers.get("www-authenticate"),
    )


def _extract_detail(response: httpx.Response) -> str | None:
    """Return the FastAPI ``detail`` field, or the raw body as a fallback."""
    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError):
        return response.text or None
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, str):
            return detail
        if detail is not None:
            return json.dumps(detail)
        # OAuth-style error bodies use error/error_description instead.
        oauth = payload.get("error_description") or payload.get("error")
        if isinstance(oauth, str):
            return oauth
    return response.text or None
