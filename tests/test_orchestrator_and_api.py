from fastapi.testclient import TestClient

from app.main import app
from app.models import ScanRequest
from app.orchestrator import FETCHERS, run_scan


client = TestClient(app)


def test_health_lists_all_fetchers():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["fetchers"] == sorted(FETCHERS)


def test_unknown_fetcher_returns_404():
    response = client.post("/fetch/unknown", json={"target": "example.com"})
    assert response.status_code == 404


def test_direct_fetch_endpoint(monkeypatch):
    monkeypatch.setitem(FETCHERS, "dns", lambda target, timeout: {"records": {"A": []}})
    response = client.post("/fetch/dns", json={"target": "example.com"})
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["data"]["records"] == {"A": []}


def test_orchestrator_keeps_success_when_one_fetcher_fails(monkeypatch):
    monkeypatch.setitem(
        FETCHERS, "web", lambda target, timeout, browser: {"title": "ok"}
    )

    def fail(target, timeout):
        raise RuntimeError("temporary DNS failure")

    monkeypatch.setitem(FETCHERS, "tls", fail)
    monkeypatch.setitem(FETCHERS, "compliance", lambda target, timeout: {"files": {}})

    result = run_scan(ScanRequest(target="example.com", scan_type="FREE_HOST"))

    assert result.status == "partial"
    assert result.results["web"].status == "ok"
    assert result.results["tls"].status == "failed"
    assert result.results["compliance"].status == "ok"


def test_direct_web_fetch_passes_browser_options(monkeypatch):
    def fake_web(target, timeout, browser):
        return {
            "javascript_enabled": browser.javascript_enabled,
            "proxy_server": browser.proxy.server,
        }

    monkeypatch.setitem(FETCHERS, "web", fake_web)
    response = client.post(
        "/fetch/web",
        json={
            "target": "https://example.com",
            "browser": {
                "javascript_enabled": True,
                "capture_screenshot": False,
                "proxy": {
                    "server": "http://proxy.example:3128",
                    "username": "researcher",
                    "password": "secret",
                },
            },
        },
    )

    assert response.status_code == 200
    assert response.json()["data"] == {
        "javascript_enabled": True,
        "proxy_server": "http://proxy.example:3128",
    }


def test_non_scannable_api_request_runs_no_fetchers():
    response = client.post(
        "/scan", json={"target": "https://example.com/file.pdf", "scan_type": "NON_SCANNABLE"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "skipped"
    assert response.json()["results"] == {}
