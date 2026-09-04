from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from time import perf_counter
from typing import Callable
from uuid import uuid4

from app.fetchers import compliance, dns, domain_rdap, ip_geo, ip_rdap, ports, tls, web
from app.models import BrowserOptions, FetcherResult, ScanRequest, ScanResponse, ScanType
from app.utils import utc_now


FetcherFunction = Callable[..., dict]

FETCHERS: dict[str, FetcherFunction] = {
    "web": web.fetch,
    "dns": dns.fetch,
    "tls": tls.fetch,
    "domain_rdap": domain_rdap.fetch,
    "ip_geo": ip_geo.fetch,
    "ip_rdap": ip_rdap.fetch,
    "compliance": compliance.fetch,
    "ports": ports.fetch,
}


SCAN_FETCHERS: dict[ScanType, list[str]] = {
    ScanType.WEB_OK: [
        "web",
        "dns",
        "tls",
        "domain_rdap",
        "ip_geo",
        "ip_rdap",
        "compliance",
        "ports",
    ],
    ScanType.RESOLVED_NO_WEB: [
        "dns",
        "tls",
        "domain_rdap",
        "ip_geo",
        "ip_rdap",
        "ports",
    ],
    ScanType.DNS_FAIL: ["domain_rdap"],
    ScanType.FREE_HOST: ["web", "tls", "compliance"],
    ScanType.EXTENSION_SCAN: ["dns", "tls", "domain_rdap"],
    ScanType.NON_SCANNABLE: [],
}


def select_fetchers(
    scan_type: ScanType, destination_scan_type: ScanType | None = None
) -> list[str]:
    if scan_type == ScanType.URL_SHORTENER:
        if destination_scan_type is None:
            raise ValueError("destination_scan_type is required for URL_SHORTENER")
        return select_fetchers(destination_scan_type)
    return list(SCAN_FETCHERS[scan_type])


def run_fetcher(
    fetcher_name: str,
    target: str,
    timeout_seconds: int,
    requested_ports: list[int] | None = None,
    browser_options: BrowserOptions | None = None,
) -> FetcherResult:
    if fetcher_name not in FETCHERS:
        raise KeyError(fetcher_name)

    started = perf_counter()
    try:
        if fetcher_name == "ports":
            data = FETCHERS[fetcher_name](target, timeout_seconds, requested_ports)
        elif fetcher_name == "web":
            data = FETCHERS[fetcher_name](target, timeout_seconds, browser_options)
        else:
            data = FETCHERS[fetcher_name](target, timeout_seconds)
        status = data.pop("_status", "ok")
        return FetcherResult(
            fetcher=fetcher_name,
            status=status,
            elapsed_ms=round((perf_counter() - started) * 1000),
            data=data,
        )
    except Exception as exc:  # One failed source must not discard other evidence.
        return FetcherResult(
            fetcher=fetcher_name,
            status="failed",
            elapsed_ms=round((perf_counter() - started) * 1000),
            error=str(exc),
        )


def _overall_status(results: dict[str, FetcherResult]) -> str:
    if not results:
        return "skipped"
    statuses = [result.status for result in results.values()]
    if all(status == "failed" for status in statuses):
        return "failed"
    if any(status in {"failed", "partial"} for status in statuses):
        return "partial"
    if all(status == "skipped" for status in statuses):
        return "skipped"
    return "ok"


def run_scan(request: ScanRequest) -> ScanResponse:
    started_at = utc_now()
    started = perf_counter()
    selected = select_fetchers(request.scan_type, request.destination_scan_type)
    results: dict[str, FetcherResult] = {}

    if selected:
        with ThreadPoolExecutor(max_workers=len(selected)) as executor:
            futures = {
                executor.submit(
                    run_fetcher,
                    name,
                    request.target,
                    request.timeout_seconds,
                    request.ports,
                    request.browser,
                ): name
                for name in selected
            }
            for future in as_completed(futures):
                name = futures[future]
                results[name] = future.result()

    finished_at = utc_now()
    return ScanResponse(
        scan_id=str(uuid4()),
        target=request.target,
        scan_type=request.scan_type,
        status=_overall_status(results),
        selected_fetchers=selected,
        started_at=started_at,
        finished_at=finished_at,
        elapsed_ms=round((perf_counter() - started) * 1000),
        results={name: results[name] for name in selected},
    )
