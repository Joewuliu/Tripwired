"""The one place that decides whether an address may be contacted.

Every request the sandbox makes, and every redirect hop, goes through is_public.
"""
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http": 80, "https": 443}


def _is_global(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%")[0])  # drop an IPv6 zone id
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 is loopback in disguise
    return ip.is_global


def is_public(url: str) -> bool:
    """True only for http(s) URLs whose host resolves exclusively to globally routable addresses.

    A name that resolves to a mix of public and private addresses is refused. Anything that
    fails to parse or resolve is refused too.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_SCHEMES or not parsed.hostname:
            return False
        port = parsed.port or ALLOWED_SCHEMES[parsed.scheme]
        infos = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
        return bool(infos) and all(_is_global(info[4][0]) for info in infos)
    except (OSError, ValueError):
        return False
