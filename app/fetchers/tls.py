from __future__ import annotations

import socket
import ssl

from app.utils import hostname_from_target


def _name_to_dict(name_parts: tuple) -> dict[str, str]:
    result: dict[str, str] = {}
    for group in name_parts:
        for key, value in group:
            result[key] = value
    return result


def fetch(target: str, timeout_seconds: int) -> dict:
    host = hostname_from_target(target)
    context = ssl.create_default_context()

    with socket.create_connection((host, 443), timeout=timeout_seconds) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
            certificate = tls_socket.getpeercert()
            cipher = tls_socket.cipher()
            return {
                "hostname": host,
                "port": 443,
                "tls_version": tls_socket.version(),
                "cipher": cipher[0] if cipher else None,
                "subject": _name_to_dict(certificate.get("subject", ())),
                "issuer": _name_to_dict(certificate.get("issuer", ())),
                "serial_number": certificate.get("serialNumber"),
                "not_before": certificate.get("notBefore"),
                "not_after": certificate.get("notAfter"),
                "subject_alternative_names": [
                    value
                    for name_type, value in certificate.get("subjectAltName", ())
                    if name_type == "DNS"
                ],
            }
