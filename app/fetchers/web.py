from __future__ import annotations

import base64
import os
from urllib.parse import urlsplit

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

from app.models import BrowserOptions, ProxySettings
from app.utils import USER_AGENT, normalize_url


MAX_BODY_BYTES = 2_000_000
MAX_NETWORK_EVENTS = 500
MAX_NETWORK_ERRORS = 50
INTERESTING_HEADERS = {
    "content-type",
    "content-length",
    "server",
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
}


def _environment_proxy() -> ProxySettings | None:
    server = os.getenv("WEB_PROXY_URL", "").strip()
    if not server:
        return None
    return ProxySettings(
        server=server,
        username=os.getenv("WEB_PROXY_USERNAME") or None,
        password=os.getenv("WEB_PROXY_PASSWORD") or None,
        bypass=os.getenv("WEB_PROXY_BYPASS") or None,
    )


def _playwright_proxy(settings: ProxySettings | None) -> dict[str, str] | None:
    if settings is None:
        return None

    proxy = {"server": settings.server}
    if settings.username:
        proxy["username"] = settings.username
    if settings.password:
        proxy["password"] = settings.password.get_secret_value()
    if settings.bypass:
        proxy["bypass"] = settings.bypass
    return proxy


def _truncate_html(html: str) -> tuple[str, bool]:
    encoded = html.encode("utf-8")
    if len(encoded) <= MAX_BODY_BYTES:
        return html, False
    return encoded[:MAX_BODY_BYTES].decode("utf-8", errors="ignore"), True


def fetch(
    target: str,
    timeout_seconds: int,
    browser_options: BrowserOptions | None = None,
) -> dict:
    """Load a page in Chromium and return bounded, rendered browser evidence."""
    url = normalize_url(target)
    options = browser_options or BrowserOptions()
    proxy_settings = options.proxy or _environment_proxy()
    proxy = _playwright_proxy(proxy_settings)
    network_events: list[dict] = []
    network_errors: list[dict] = []
    redirect_chain: list[dict] = []
    warnings: list[str] = []
    network_truncated = False
    main_response = None
    last_navigation_status = None
    last_navigation_headers: dict[str, str] = {}

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            proxy=proxy,
            args=["--disable-dev-shm-usage"],
        )
        try:
            context = browser.new_context(
                viewport={
                    "width": options.viewport_width,
                    "height": options.viewport_height,
                },
                user_agent=USER_AGENT,
                java_script_enabled=options.javascript_enabled,
                ignore_https_errors=True,
            )
            page = context.new_page()
            page.set_default_timeout(timeout_seconds * 1000)

            def record_response(response) -> None:
                nonlocal network_truncated, last_navigation_status
                nonlocal last_navigation_headers
                request = response.request
                if request.is_navigation_request() and request.frame == page.main_frame:
                    redirect_chain.append(
                        {"url": response.url, "status_code": response.status}
                    )
                    last_navigation_status = response.status
                    last_navigation_headers = response.headers
                if not options.capture_network:
                    return
                if len(network_events) >= MAX_NETWORK_EVENTS:
                    network_truncated = True
                    return
                network_events.append(
                    {
                        "url": response.url,
                        "method": request.method,
                        "resource_type": request.resource_type,
                        "status_code": response.status,
                        "content_type": response.headers.get("content-type", ""),
                    }
                )

            def record_failure(request) -> None:
                if not options.capture_network or len(network_errors) >= MAX_NETWORK_ERRORS:
                    return
                network_errors.append(
                    {
                        "url": request.url,
                        "method": request.method,
                        "resource_type": request.resource_type,
                        "error": request.failure or "request failed",
                    }
                )

            page.on("response", record_response)
            page.on("requestfailed", record_failure)

            try:
                main_response = page.goto(
                    url,
                    wait_until=options.wait_until,
                    timeout=timeout_seconds * 1000,
                )
            except PlaywrightTimeoutError:
                warnings.append("page load reached the configured timeout")

            if options.post_load_wait_ms:
                page.wait_for_timeout(options.post_load_wait_ms)

            final_url = page.url
            html, body_truncated = _truncate_html(page.content())
            title = page.title()
            description = page.evaluate(
                """() => {
                    const element = document.querySelector('meta[name="description"]');
                    return element ? element.content : '';
                }"""
            )
            raw_links = page.eval_on_selector_all(
                "a[href]",
                """elements => elements.map(element => ({
                    url: element.href,
                    title: (element.innerText || element.textContent || '').trim()
                }))""",
            )

            final_host = (urlsplit(final_url).hostname or "").lower()
            links: list[dict[str, str]] = []
            domains: set[str] = set()
            seen: set[str] = set()
            for item in raw_links:
                absolute_url = item.get("url", "").split("#", 1)[0]
                parsed = urlsplit(absolute_url)
                if (
                    parsed.scheme not in {"http", "https"}
                    or not parsed.hostname
                    or absolute_url in seen
                ):
                    continue
                seen.add(absolute_url)
                domain = parsed.hostname.lower()
                if domain != final_host:
                    domains.add(domain)
                    links.append(
                        {
                            "url": absolute_url,
                            "title": item.get("title", ""),
                            "domain": domain,
                        }
                    )

            screenshot = None
            if options.capture_screenshot:
                try:
                    image = page.screenshot(type="png", full_page=False)
                    screenshot = base64.b64encode(image).decode("ascii")
                except PlaywrightError as exc:
                    warnings.append(f"screenshot capture failed: {exc}")

            response_headers = (
                main_response.headers if main_response else last_navigation_headers
            )
            headers = {
                key.lower(): value
                for key, value in response_headers.items()
                if key.lower() in INTERESTING_HEADERS
            }
            status_code = (
                main_response.status if main_response else last_navigation_status
            )

            result = {
                "requested_url": url,
                "final_url": final_url,
                "status_code": status_code,
                "content_type": response_headers.get("content-type", ""),
                "headers": headers,
                "title": title,
                "description": description.strip(),
                "redirect_chain": redirect_chain,
                "outgoing_links": links,
                "outgoing_domains": sorted(domains),
                "html": html,
                "body_truncated": body_truncated,
                "javascript_enabled": options.javascript_enabled,
                "proxy_used": proxy is not None,
                "screenshot_base64": screenshot,
                "screenshot_format": "png" if screenshot else None,
                "network_events": network_events,
                "network_errors": network_errors,
                "network_events_truncated": network_truncated,
                "warnings": warnings,
            }
            if warnings:
                result["_status"] = "partial"
            return result
        finally:
            browser.close()
