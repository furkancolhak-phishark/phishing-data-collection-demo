from __future__ import annotations

import os
from urllib.parse import quote

import requests

from app.utils import USER_AGENT, resolve_ip


IP_GEO_BASE_URL = os.getenv("IP_GEO_BASE_URL", "https://ipwho.is")


def fetch(target: str, timeout_seconds: int) -> dict:
    ip = resolve_ip(target)
    url = f"{IP_GEO_BASE_URL.rstrip('/')}/{quote(ip, safe=':')}"
    response = requests.get(url, timeout=timeout_seconds, headers={"User-Agent": USER_AGENT})
    response.raise_for_status()
    raw = response.json()
    if raw.get("success") is False:
        raise ValueError(raw.get("message", "IP geolocation provider returned an error"))

    connection = raw.get("connection") or {}
    timezone = raw.get("timezone") or {}
    return {
        "ip": raw.get("ip", ip),
        "continent": raw.get("continent"),
        "country": raw.get("country"),
        "country_code": raw.get("country_code"),
        "region": raw.get("region"),
        "city": raw.get("city"),
        "latitude": raw.get("latitude"),
        "longitude": raw.get("longitude"),
        "timezone": timezone.get("id"),
        "asn": connection.get("asn"),
        "organization": connection.get("org"),
        "isp": connection.get("isp"),
    }
