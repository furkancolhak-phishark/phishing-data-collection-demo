import pytest
from pydantic import ValidationError

from app.models import BrowserOptions, FetchRequest, ProxySettings, ScanRequest, ScanType
from app.orchestrator import select_fetchers


def test_scan_type_selection_table():
    assert select_fetchers(ScanType.WEB_OK) == [
        "web",
        "dns",
        "tls",
        "domain_rdap",
        "ip_geo",
        "ip_rdap",
        "compliance",
        "ports",
    ]
    assert select_fetchers(ScanType.RESOLVED_NO_WEB) == [
        "dns",
        "tls",
        "domain_rdap",
        "ip_geo",
        "ip_rdap",
        "ports",
    ]
    assert select_fetchers(ScanType.DNS_FAIL) == ["domain_rdap"]
    assert select_fetchers(ScanType.FREE_HOST) == ["web", "tls", "compliance"]
    assert select_fetchers(ScanType.EXTENSION_SCAN) == ["dns", "tls", "domain_rdap"]
    assert select_fetchers(ScanType.NON_SCANNABLE) == []


def test_url_shortener_delegates_to_destination_type():
    request = ScanRequest(
        target="https://short.example/x",
        scan_type="URL_SHORTENER",
        destination_scan_type="FREE_HOST",
    )
    assert select_fetchers(request.scan_type, request.destination_scan_type) == [
        "web",
        "tls",
        "compliance",
    ]


def test_url_shortener_requires_destination_type():
    with pytest.raises(ValidationError):
        ScanRequest(target="short.example", scan_type="URL_SHORTENER")


def test_request_accepts_port_22_and_removes_duplicates():
    request = FetchRequest(target="localhost", ports=[22, 80, 22])
    assert request.ports == [22, 80]


@pytest.mark.parametrize("port", [0, 65536])
def test_request_rejects_invalid_ports(port):
    with pytest.raises(ValidationError):
        FetchRequest(target="localhost", ports=[port])


@pytest.mark.parametrize("timeout", [0, 121])
def test_request_rejects_invalid_timeout(timeout):
    with pytest.raises(ValidationError):
        FetchRequest(target="localhost", timeout_seconds=timeout)


def test_browser_defaults_execute_javascript_and_capture_evidence():
    options = BrowserOptions()
    assert options.javascript_enabled is True
    assert options.capture_screenshot is True
    assert options.capture_network is True


@pytest.mark.parametrize(
    "server", ["ftp://proxy.example:21", "http://", "http://user:pass@proxy.example"]
)
def test_proxy_rejects_unsafe_or_invalid_server_values(server):
    with pytest.raises(ValidationError):
        ProxySettings(server=server)
