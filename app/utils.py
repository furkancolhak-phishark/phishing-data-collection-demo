from __future__ import annotations

import ipaddress
import socket
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit


USER_AGENT = "PhishingDataCollectionDemo/1.0 (academic research example)"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_url(target: str) -> str:
    """Return a usable HTTP(S) URL without hiding malformed input."""
    value = target.strip()
    if "://" not in value:
        value = "https://" + value

    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("target must use http or https")
    if not parsed.hostname:
        raise ValueError("target must contain a hostname")
    if parsed.username or parsed.password:
        raise ValueError("credentials in target URLs are not supported")

    path = parsed.path or "/"
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))


def hostname_from_target(target: str) -> str:
    value = target.strip()
    parsed = urlsplit(value if "://" in value else "//" + value)
    host = parsed.hostname
    if not host:
        raise ValueError("target must contain a hostname or IP address")
    return host.rstrip(".").lower()


def resolve_ip(target: str) -> str:
    host = hostname_from_target(target)
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    if not addresses:
        raise OSError(f"could not resolve {host}")
    return addresses[0][4][0]


def base_url(target: str) -> str:
    parsed = urlsplit(normalize_url(target))
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
