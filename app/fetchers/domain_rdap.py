from __future__ import annotations

import os
from urllib.parse import quote

import requests

from app.utils import USER_AGENT, hostname_from_target


RDAP_BASE_URL = os.getenv("DOMAIN_RDAP_BASE_URL", "https://rdap.org/domain")


def _entity_name(entity: dict) -> str:
    vcard = entity.get("vcardArray", [])
    if len(vcard) != 2 or not isinstance(vcard[1], list):
        return entity.get("handle", "")
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] in {"fn", "org"}:
            return str(item[3])
    return entity.get("handle", "")


def fetch(target: str, timeout_seconds: int) -> dict:
    domain = hostname_from_target(target)
    url = f"{RDAP_BASE_URL.rstrip('/')}/{quote(domain, safe='')}"
    response = requests.get(
        url,
        timeout=timeout_seconds,
        headers={"Accept": "application/rdap+json", "User-Agent": USER_AGENT},
    )
    response.raise_for_status()
    raw = response.json()

    registrar = None
    for entity in raw.get("entities", []):
        if "registrar" in entity.get("roles", []):
            registrar = {
                "handle": entity.get("handle"),
                "name": _entity_name(entity),
            }
            break

    events = {
        item.get("eventAction", "unknown"): item.get("eventDate")
        for item in raw.get("events", [])
        if item.get("eventDate")
    }
    nameservers = sorted(
        item.get("ldhName", "").lower()
        for item in raw.get("nameservers", [])
        if item.get("ldhName")
    )
    return {
        "domain": raw.get("ldhName", domain).lower(),
        "handle": raw.get("handle"),
        "status": raw.get("status", []),
        "events": events,
        "nameservers": nameservers,
        "registrar": registrar,
        "port43": raw.get("port43"),
        "raw_response": raw,
    }
