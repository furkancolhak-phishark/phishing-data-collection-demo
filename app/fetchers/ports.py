from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, wait
from time import perf_counter

from app.utils import hostname_from_target, resolve_ip


MAX_WORKERS = 100


def _is_open(ip: str, port: int, connect_timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=connect_timeout):
            return True
    except OSError:
        return False


def fetch(target: str, timeout_seconds: int, ports: list[int] | None = None) -> dict:
    requested_ports = list(dict.fromkeys(ports or []))
    if not requested_ports:
        return {
            "_status": "skipped",
            "reason": "no ports were supplied",
            "scanned_ports": [],
            "open_ports": [],
        }

    invalid = [port for port in requested_ports if port < 1 or port > 65535]
    if invalid:
        raise ValueError("ports must be between 1 and 65535")

    started = perf_counter()
    ip = resolve_ip(target)
    host = hostname_from_target(target)
    connect_timeout = min(1.0, max(0.1, timeout_seconds / 10))
    executor = ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(requested_ports)))
    futures = {
        executor.submit(_is_open, ip, port, connect_timeout): port
        for port in requested_ports
    }
    done, pending = wait(futures, timeout=timeout_seconds)
    for future in pending:
        future.cancel()
    executor.shutdown(wait=False, cancel_futures=True)

    scanned_ports = sorted(futures[future] for future in done)
    open_ports = sorted(futures[future] for future in done if future.result())
    status = "partial" if pending else "ok"
    return {
        "_status": status,
        "hostname": host,
        "resolved_ip": ip,
        "requested_ports": requested_ports,
        "scanned_ports": scanned_ports,
        "open_ports": open_ports,
        "unfinished_ports": sorted(futures[future] for future in pending),
        "scan_duration_ms": round((perf_counter() - started) * 1000),
    }
