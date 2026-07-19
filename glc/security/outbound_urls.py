"""Validation for credential-bearing outbound provider requests."""

from __future__ import annotations

from collections.abc import Collection
from urllib.parse import urlsplit


class UnsafeOutboundURL(ValueError):
    """Raised when an outbound URL falls outside its provider boundary."""


def _host_allowed(host: str, allowed_hosts: Collection[str]) -> bool:
    host = host.lower().rstrip(".")
    for entry in allowed_hosts:
        entry = entry.lower().rstrip(".")
        if entry.startswith("*."):
            suffix = entry[2:]
            if suffix and host.endswith(f".{suffix}"):
                return True
        elif host == entry:
            return True
    return False


def validate_provider_url(
    url: str,
    *,
    allowed_hosts: Collection[str],
    allow_query: bool = True,
) -> str:
    """Return canonical HTTPS URL only when its host belongs to provider."""
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise UnsafeOutboundURL("provider URL must use HTTPS and include a host")
    if parsed.username or parsed.password:
        raise UnsafeOutboundURL("provider URL must not include credentials")
    try:
        port = parsed.port
    except ValueError as exc:
        raise UnsafeOutboundURL("provider URL has an invalid port") from exc
    if port not in (None, 443):
        raise UnsafeOutboundURL("provider URL must use port 443")
    if parsed.fragment or (parsed.query and not allow_query):
        raise UnsafeOutboundURL("provider URL contains unsupported components")

    host = parsed.hostname.lower().rstrip(".")
    if not _host_allowed(host, allowed_hosts):
        raise UnsafeOutboundURL("provider URL host is not allowlisted")

    netloc = host if port is None else f"{host}:{port}"
    return parsed._replace(scheme="https", netloc=netloc, fragment="").geturl()
