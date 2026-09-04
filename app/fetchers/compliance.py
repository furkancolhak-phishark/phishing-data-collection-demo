from __future__ import annotations

import re
from urllib.parse import urljoin

import requests

from app.utils import USER_AGENT, base_url


STANDARD_FILES = {
    "security_txt": ["/.well-known/security.txt", "/security.txt"],
    "robots_txt": ["/robots.txt"],
    "sitemap_xml": ["/sitemap.xml"],
    "humans_txt": ["/humans.txt"],
    "llms_txt": ["/llms.txt"],
    "ads_txt": ["/ads.txt"],
    "app_ads_txt": ["/app-ads.txt"],
}


def _check_url(url: str, timeout_seconds: int) -> dict:
    response = requests.get(
        url,
        timeout=timeout_seconds,
        allow_redirects=True,
        stream=True,
        headers={"User-Agent": USER_AGENT},
    )
    content_type = response.headers.get("content-type", "")
    return {
        "url": response.url,
        "exists": 200 <= response.status_code < 300,
        "status_code": response.status_code,
        "content_type": content_type,
    }


def fetch(target: str, timeout_seconds: int) -> dict:
    root = base_url(target)
    files: dict[str, dict] = {}

    for name, paths in STANDARD_FILES.items():
        last_result = None
        for path in paths:
            try:
                result = _check_url(urljoin(root + "/", path.lstrip("/")), timeout_seconds)
            except requests.RequestException as exc:
                last_result = {"url": urljoin(root, path), "exists": False, "error": str(exc)}
                continue
            last_result = result
            if result["exists"]:
                break
        files[name] = last_result or {"exists": False}

    robots = files.get("robots_txt", {})
    sitemaps: list[str] = []
    if robots.get("exists"):
        try:
            response = requests.get(
                robots["url"], timeout=timeout_seconds, headers={"User-Agent": USER_AGENT}
            )
            sitemaps = re.findall(r"(?im)^sitemap:\s*(\S+)", response.text)
        except requests.RequestException:
            pass

    return {"base_url": root, "files": files, "sitemaps_from_robots": sitemaps}
