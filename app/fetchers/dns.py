from __future__ import annotations

import dns.exception
import dns.resolver

from app.utils import hostname_from_target


RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA")


def _format_record(record_type: str, record) -> object:
    if record_type == "MX":
        return {
            "priority": int(record.preference),
            "host": str(record.exchange).rstrip("."),
        }
    if record_type == "SOA":
        return {
            "mname": str(record.mname).rstrip("."),
            "rname": str(record.rname).rstrip("."),
            "serial": int(record.serial),
            "refresh": int(record.refresh),
            "retry": int(record.retry),
            "expire": int(record.expire),
            "minimum": int(record.minimum),
        }
    if record_type == "CAA":
        value = record.value.decode() if isinstance(record.value, bytes) else str(record.value)
        tag = record.tag.decode() if isinstance(record.tag, bytes) else str(record.tag)
        return {"flags": int(record.flags), "tag": tag, "value": value}
    if record_type == "TXT":
        return b"".join(record.strings).decode(errors="replace")
    return str(record).rstrip(".")


def query_record(host: str, record_type: str, timeout_seconds: int) -> list[object]:
    resolver = dns.resolver.Resolver()
    answer = resolver.resolve(host, record_type, lifetime=timeout_seconds)
    return [_format_record(record_type, record) for record in answer]


def fetch(target: str, timeout_seconds: int) -> dict:
    host = hostname_from_target(target)
    records: dict[str, list[object]] = {}
    errors: dict[str, str] = {}

    for record_type in RECORD_TYPES:
        try:
            records[record_type] = query_record(host, record_type, timeout_seconds)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as exc:
            records[record_type] = []
            errors[record_type] = exc.__class__.__name__
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            records[record_type] = []
            errors[record_type] = str(exc)

    return {"hostname": host, "records": records, "errors": errors}
