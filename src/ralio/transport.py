"""DPoP-bound HTTP transport.

Every request carries ``Authorization: DPoP <token>`` plus a freshly-signed
``DPoP`` proof for that exact method + URL + token. On a 401 the transport
refreshes the token once and retries with a brand-new proof (the proof ``jti``
is single-use server-side, so the retry must re-sign).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from . import _crypto
from .auth import TokenManager
from .errors import RalioAPIError, raise_for_response
from .types import ChatStreamEvent


class Transport:
    def __init__(
        self,
        *,
        base_url: str,
        http: httpx.Client,
        tokens: TokenManager,
        private_key: EllipticCurvePrivateKey,
        public_jwk: dict[str, str],
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._http = http
        self._tokens = tokens
        self._private_key = private_key
        self._public_jwk = public_jwk

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        url = self._url(path)
        response = self._http.request(
            method, url, json=json_body, params=params, headers=self._auth_headers(method, url)
        )
        if response.status_code == 401:
            self._tokens.force_refresh()
            response = self._http.request(
                method,
                url,
                json=json_body,
                params=params,
                headers=self._auth_headers(method, url),
            )
        raise_for_response(response)
        return response

    def stream_sse(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
    ) -> Iterator[ChatStreamEvent]:
        url = self._url(path)
        headers = {**self._auth_headers(method, url), "Accept": "text/event-stream"}
        with self._http.stream(method, url, json=json_body, headers=headers) as response:
            if response.status_code == 401:
                response.read()
                self._tokens.force_refresh()
                headers = {**self._auth_headers(method, url), "Accept": "text/event-stream"}
                with self._http.stream(
                    method, url, json=json_body, headers=headers
                ) as retry:
                    yield from _parse_sse(_checked(retry))
                    return
            yield from _parse_sse(_checked(response))

    def _url(self, path: str) -> str:
        return f"{self._base_url}{path}"

    def _auth_headers(self, method: str, url: str) -> dict[str, str]:
        token = self._tokens.access_token()
        proof = _crypto.sign_dpop_proof(
            self._private_key,
            method=method,
            url=_htu(url),
            access_token=token,
            jwk=self._public_jwk,
        )
        return {"Authorization": f"DPoP {token}", "DPoP": proof}


def _htu(url: str) -> str:
    """Strip query and fragment — the ``htu`` claim must be scheme+host+path."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _checked(response: httpx.Response) -> httpx.Response:
    if not response.is_success:
        response.read()
        raise_for_response(response)
    return response


def _parse_sse(response: httpx.Response) -> Iterator[ChatStreamEvent]:
    """Yield ``ChatStreamEvent`` per SSE record (blank-line delimited)."""
    event_name = "message"
    data_lines: list[str] = []
    for line in response.iter_lines():
        if line == "":
            if data_lines:
                yield _build_event(event_name, data_lines)
            event_name = "message"
            data_lines = []
            continue
        if line.startswith(":"):
            continue  # comment / keep-alive
        field, _, value = line.partition(":")
        value = value[1:] if value.startswith(" ") else value
        if field == "event":
            event_name = value
        elif field == "data":
            data_lines.append(value)
    if data_lines:
        yield _build_event(event_name, data_lines)


def _build_event(event_name: str, data_lines: list[str]) -> ChatStreamEvent:
    raw = "\n".join(data_lines)
    try:
        payload = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        payload = {"raw": raw}
    if not isinstance(payload, dict):
        payload = {"value": payload}
    if event_name == "error":
        raise RalioAPIError(
            payload.get("message", "stream error"),
            status_code=200,
            detail=payload.get("message"),
        )
    return ChatStreamEvent(event=event_name, data=payload)
