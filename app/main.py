from __future__ import annotations

from fastapi import FastAPI, HTTPException

from app.models import FetchRequest, FetcherResult, ScanRequest, ScanResponse
from app.orchestrator import FETCHERS, run_fetcher, run_scan


app = FastAPI(
    title="Phishing Data Collection Demo",
    description="A small educational API for collecting web and network metadata.",
    version="1.1.0",
)


@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "ok", "fetchers": sorted(FETCHERS)}


@app.post("/fetch/{fetcher_name}", response_model=FetcherResult)
def fetch_one(fetcher_name: str, request: FetchRequest) -> FetcherResult:
    if fetcher_name not in FETCHERS:
        raise HTTPException(
            status_code=404,
            detail={"message": "unknown fetcher", "available": sorted(FETCHERS)},
        )
    return run_fetcher(
        fetcher_name,
        request.target,
        request.timeout_seconds,
        request.ports,
        request.browser,
    )


@app.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest) -> ScanResponse:
    return run_scan(request)
