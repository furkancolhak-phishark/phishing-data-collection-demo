from __future__ import annotations

import os
from urllib.parse import quote

import requests

from app.fetchers.domain_rdap import _entity_name
from app.utils import USER_AGENT, resolve_ip


IP_RDAP_BASE_URL = os.getenv("IP_RDAP_BASE_URL", "https://rdap.org/ip")


def fetch(target: str, timeout_seconds: int) -> dict:
    ip = resolve_ip(target)
    url = f"{IP_RDAP_BASE_URL.rstrip('/')}/{quote(ip, safe=':')}"
    response = requests.get(
        url,
        timeout=timeout_seconds,
        headers={"Accept": "application/rdap+json", "User-Agent": USER_AGENT},
    )
    response.raise_for_status()
    raw = response.json()

    organizations = []
    for entity in raw.get("entities", []):
        name = _entity_name(entity)
        if name and name not in organizations:
            organizations.append(name)

    events = {
        item.get("eventAction", "unknown"): item.get("eventDate")
        for item in raw.get("events", [])
        if item.get("eventDate")
    }
    return {
        "ip": ip,
        "handle": raw.get("handle"),
        "name": raw.get("name"),
        "type": raw.get("type"),
        "cidrs": raw.get("cidr0_cidrs", []),
        "start_address": raw.get("startAddress"),
        "end_address": raw.get("endAddress"),
        "country": raw.get("country"),
        "status": raw.get("status", []),
        "organizations": organizations,
        "events": events,
        "port43": raw.get("port43"),
        "raw_response": raw,
    }
