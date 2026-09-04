from __future__ import annotations

import base64
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.fetchers import compliance, dns, domain_rdap, ip_geo, ip_rdap, ports, tls, web
from app.models import BrowserOptions, ProxySettings


class FakeResponse:
    def __init__(
        self,
        *,
        url="https://example.com/",
        status_code=200,
        body=b"",
        headers=None,
        json_data=None,
        history=None,
    ):
        self.url = url
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self._json_data = json_data or {}
        self.history = history or []
        self.encoding = "utf-8"
        self.text = body.decode("utf-8", errors="replace")

    def iter_content(self, chunk_size=1):
        yield self._body

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class JavaScriptPageHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/start":
            self.send_response(302)
            self.send_header("Location", "/page")
            self.end_headers()
            return

        body = b"""<html><head><title>Before JavaScript</title>
            <meta name="description" content="A rendered page"></head>
            <body><script>
              document.title = 'After JavaScript';
              const link = document.createElement('a');
              link.href = 'https://outside.test/path';
              link.textContent = 'Dynamic link';
              document.body.appendChild(link);
            </script></body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def test_web_fetcher_runs_javascript_and_collects_browser_evidence():
    server = ThreadingHTTPServer(("127.0.0.1", 0), JavaScriptPageHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f"http://127.0.0.1:{server.server_port}/start"
    try:
        result = web.fetch(
            target,
            10,
            BrowserOptions(post_load_wait_ms=50, capture_screenshot=True),
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result["title"] == "After JavaScript"
    assert result["description"] == "A rendered page"
    assert result["outgoing_domains"] == ["outside.test"]
    assert result["headers"]["x-frame-options"] == "DENY"
    assert [item["status_code"] for item in result["redirect_chain"]] == [302, 200]
    assert any(item["resource_type"] == "document" for item in result["network_events"])
    assert base64.b64decode(result["screenshot_base64"]).startswith(b"\x89PNG")


def test_web_proxy_settings_are_passed_to_playwright():
    proxy = ProxySettings(
        server="socks5://proxy.example:1080",
        username="researcher",
        password="secret",
        bypass="localhost,127.0.0.1",
    )

    assert web._playwright_proxy(proxy) == {
        "server": "socks5://proxy.example:1080",
        "username": "researcher",
        "password": "secret",
        "bypass": "localhost,127.0.0.1",
    }


def test_dns_fetcher_keeps_each_record_family(monkeypatch):
    values = {record_type: [record_type.lower()] for record_type in dns.RECORD_TYPES}
    monkeypatch.setattr(dns, "query_record", lambda host, kind, timeout: values[kind])

    result = dns.fetch("https://example.com/path", 5)

    assert result["hostname"] == "example.com"
    assert result["records"]["A"] == ["a"]
    assert result["records"]["SOA"] == ["soa"]


class FakeTLSSocket:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def getpeercert(self):
        return {
            "subject": ((('commonName', 'example.com'),),),
            "issuer": ((('organizationName', 'Example CA'),),),
            "serialNumber": "01",
            "notBefore": "Jan 1 00:00:00 2026 GMT",
            "notAfter": "Jan 1 00:00:00 2027 GMT",
            "subjectAltName": (("DNS", "example.com"),),
        }

    def cipher(self):
        return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)

    def version(self):
        return "TLSv1.3"


class FakeContext:
    def wrap_socket(self, raw_socket, server_hostname):
        return FakeTLSSocket()


class FakeRawSocket:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_tls_fetcher_normalizes_certificate(monkeypatch):
    monkeypatch.setattr(tls.ssl, "create_default_context", lambda: FakeContext())
    monkeypatch.setattr(tls.socket, "create_connection", lambda *args, **kwargs: FakeRawSocket())

    result = tls.fetch("example.com", 5)

    assert result["tls_version"] == "TLSv1.3"
    assert result["subject"]["commonName"] == "example.com"
    assert result["issuer"]["organizationName"] == "Example CA"


def test_domain_rdap_fetcher_normalizes_response(monkeypatch):
    raw = {
        "ldhName": "EXAMPLE.COM",
        "handle": "123",
        "status": ["active"],
        "events": [{"eventAction": "registration", "eventDate": "1995-08-14"}],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
        "entities": [
            {
                "handle": "REG-1",
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
            }
        ],
    }
    monkeypatch.setattr(
        domain_rdap.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(json_data=raw),
    )

    result = domain_rdap.fetch("example.com", 5)

    assert result["domain"] == "example.com"
    assert result["registrar"]["name"] == "Example Registrar"
    assert result["nameservers"] == ["ns1.example.com"]


def test_ip_geo_fetcher_normalizes_provider_fields(monkeypatch):
    raw = {
        "success": True,
        "ip": "203.0.113.10",
        "country": "Exampleland",
        "country_code": "EX",
        "timezone": {"id": "Etc/UTC"},
        "connection": {"asn": 64500, "org": "Example Org", "isp": "Example ISP"},
    }
    monkeypatch.setattr(ip_geo, "resolve_ip", lambda target: "203.0.113.10")
    monkeypatch.setattr(
        ip_geo.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(json_data=raw),
    )

    result = ip_geo.fetch("example.com", 5)

    assert result["ip"] == "203.0.113.10"
    assert result["asn"] == 64500
    assert result["timezone"] == "Etc/UTC"


def test_ip_rdap_fetcher_normalizes_allocation(monkeypatch):
    raw = {
        "handle": "NET-TEST",
        "name": "TEST-NET",
        "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}],
        "startAddress": "203.0.113.0",
        "endAddress": "203.0.113.255",
        "country": "EX",
        "entities": [{"handle": "ORG-TEST", "vcardArray": []}],
    }
    monkeypatch.setattr(ip_rdap, "resolve_ip", lambda target: "203.0.113.10")
    monkeypatch.setattr(
        ip_rdap.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(json_data=raw),
    )

    result = ip_rdap.fetch("example.com", 5)

    assert result["start_address"] == "203.0.113.0"
    assert result["cidrs"] == [{"v4prefix": "203.0.113.0", "length": 24}]
    assert result["organizations"] == ["ORG-TEST"]


def test_compliance_fetcher_reports_standard_files(monkeypatch):
    def fake_get(url, **kwargs):
        if url.endswith("robots.txt"):
            return FakeResponse(url=url, body=b"Sitemap: https://example.com/map.xml")
        if url.endswith("security.txt"):
            return FakeResponse(url=url)
        return FakeResponse(url=url, status_code=404)

    monkeypatch.setattr(compliance.requests, "get", fake_get)
    result = compliance.fetch("example.com", 5)

    assert result["files"]["robots_txt"]["exists"] is True
    assert result["files"]["security_txt"]["exists"] is True
    assert result["sitemaps_from_robots"] == ["https://example.com/map.xml"]


def test_port_fetcher_finds_a_local_open_port():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    open_port = server.getsockname()[1]
    try:
        result = ports.fetch("127.0.0.1", 2, [open_port])
    finally:
        server.close()

    assert result["_status"] == "ok"
    assert result["open_ports"] == [open_port]


def test_port_fetcher_skips_an_empty_list():
    result = ports.fetch("localhost", 2, [])
    assert result["_status"] == "skipped"
