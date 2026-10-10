"""The one place that decides whether an address may be contacted.

Every request the sandbox makes, and every redirect hop, goes through is_public.
"""
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http": 80, "https": 443}

NOT_WEB = "not an http(s) address"
UNRESOLVED = "the name does not resolve"
NOT_PUBLIC = "not a public address"


def _is_global(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%")[0])  # drop an IPv6 zone id
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 is loopback in disguise
    return ip.is_global


def refusal_reason(url: str) -> str | None:
    """Why this address must not be contacted (NOT_WEB, UNRESOLVED or NOT_PUBLIC), or None if it may.

    Only http(s) URLs whose host resolves exclusively to globally routable addresses pass. A name
    that resolves to a mix of public and private addresses is refused.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_SCHEMES or not parsed.hostname:
            return NOT_WEB
        port = parsed.port or ALLOWED_SCHEMES[parsed.scheme]
    except ValueError:
        return NOT_WEB
    try:
        infos = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except (OSError, ValueError):
        return UNRESOLVED
    if not infos:
        return UNRESOLVED
    try:
        return None if all(_is_global(info[4][0]) for info in infos) else NOT_PUBLIC
    except ValueError:
        return NOT_PUBLIC


def is_public(url: str) -> bool:
    """True only when the address may be contacted. Anything that fails to parse or resolve is refused."""
    return refusal_reason(url) is None
