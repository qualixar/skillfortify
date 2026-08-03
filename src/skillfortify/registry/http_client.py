"""Shared async HTTP client utilities for registry scanners.

Provides a thin wrapper around ``httpx.AsyncClient`` with standardised
timeouts, user-agent headers, and error handling. All registry scanners
use this module so that HTTP behaviour is consistent and testable.

Raises ``RegistryScanError`` (a subclass of ``SkillFortifyError``) on
unrecoverable HTTP failures.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

from skillfortify.exceptions import RegistryScanError

logger = logging.getLogger(__name__)

# Timeout for all registry HTTP requests (seconds).
DEFAULT_TIMEOUT: float = 30.0

# User-Agent sent with every request.
USER_AGENT: str = "SkillFortify-RegistryScanner/0.2"


def _ensure_httpx() -> Any:
    """Lazily import httpx and raise a friendly error if missing.

    Returns:
        The ``httpx`` module.

    Raises:
        SystemExit: If httpx is not installed.
    """
    try:
        import httpx

        return httpx
    except ImportError:
        raise SystemExit(
            "httpx is required for registry scanning.\n"
            "Install it with: pip install skillfortify[registry]"
        )


# ---------------------------------------------------------------------------
# SSRF and resource-exhaustion guards
# ---------------------------------------------------------------------------

# Maximum response body accepted from a registry. Without a cap, a hostile or
# malfunctioning endpoint can exhaust memory simply by streaming forever.
MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MiB

# Only these schemes are fetchable. `file://`, `ftp://` and friends are not
# registry transports and would turn a scanner into a local file reader.
_ALLOWED_SCHEMES = frozenset({"https", "http"})


def _is_public_address(hostname: str) -> bool:
    """Return True when ``hostname`` resolves only to public, routable addresses.

    A registry scanner fetches URLs that may originate in scanned content, so
    it must be constrained to public destinations. Loopback, private,
    link-local and reserved ranges are refused; on cloud hosts the link-local
    range in particular exposes instance credentials via the metadata service.

    Resolution failures return False: unresolvable is not provably public.
    """
    if not hostname:
        return False
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, UnicodeError, ValueError):
        return False

    for info in infos:
        address = info[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False
    return True


def is_fetchable_url(url: str) -> bool:
    """Validate a URL before any network request is made.

    Checks the scheme and refuses any host that resolves to a non-public
    address. Applied to the initial URL and re-applied to every redirect
    target, since a permitted host can redirect to an internal one.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return False
    return _is_public_address(parsed.hostname or "")


async def _get_guarded(client: Any, url: str, params: dict[str, str] | None = None) -> Any:
    """Perform a GET, validating the URL and every redirect hop.

    Redirects are followed manually so that every hop is re-validated;
    delegating redirects to the client would apply validation only to the
    first request.
    """
    current = url
    for _ in range(MAX_REDIRECTS):
        if not is_fetchable_url(current):
            raise RegistryScanError(f"Refusing to fetch non-public or unsupported URL: {current}")
        resp = await client.get(current, params=params, follow_redirects=False)
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location")
            if not location:
                break
            current = urljoin(current, location)
            params = None  # query is carried by the Location header
            continue
        return resp
    raise RegistryScanError(f"Too many redirects fetching {url}")


def _read_capped(resp: Any, url: str) -> str:
    """Return the response body, refusing anything over ``MAX_RESPONSE_BYTES``."""
    content = resp.content
    if len(content) > MAX_RESPONSE_BYTES:
        raise RegistryScanError(
            f"Response from {url} exceeds {MAX_RESPONSE_BYTES} bytes; refusing to buffer it"
        )
    return content.decode(resp.encoding or "utf-8", errors="replace")


# Bound on redirect hops, each of which is re-validated.
MAX_REDIRECTS = 5


async def fetch_json(
    url: str,
    *,
    params: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any] | list[Any]:
    """Fetch a URL and parse the response as JSON.

    Args:
        url: The URL to fetch.
        params: Optional query parameters.
        timeout: Request timeout in seconds.

    Returns:
        Parsed JSON response (dict or list).

    Raises:
        RegistryScanError: On HTTP errors, timeouts, or invalid JSON.
    """
    httpx = _ensure_httpx()
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            resp = await _get_guarded(client, url, params)
            resp.raise_for_status()
            return json.loads(_read_capped(resp, url))
    except httpx.TimeoutException:
        logger.warning("Timeout fetching %s", url)
        return {}
    except httpx.HTTPStatusError as exc:
        logger.warning("HTTP %d from %s", exc.response.status_code, url)
        return {}
    except (httpx.RequestError, ValueError) as exc:
        logger.warning("Request error for %s: %s", url, exc)
        return {}
    except RegistryScanError as exc:
        logger.warning("Refused request for %s: %s", url, exc)
        return {}


async def fetch_text(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> str:
    """Fetch a URL and return the response body as text.

    Args:
        url: The URL to fetch.
        timeout: Request timeout in seconds.

    Returns:
        Response body text. Empty string on any error.
    """
    httpx = _ensure_httpx()
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            resp = await _get_guarded(client, url)
            resp.raise_for_status()
            return _read_capped(resp, url)
    except (httpx.TimeoutException, httpx.HTTPStatusError, httpx.RequestError):
        logger.warning("Failed to fetch text from %s", url)
        return ""
    except RegistryScanError as exc:
        logger.warning("Refused request for %s: %s", url, exc)
        return ""
