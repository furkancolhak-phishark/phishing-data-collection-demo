from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator


class ScanType(str, Enum):
    WEB_OK = "WEB_OK"
    RESOLVED_NO_WEB = "RESOLVED_NO_WEB"
    DNS_FAIL = "DNS_FAIL"
    FREE_HOST = "FREE_HOST"
    EXTENSION_SCAN = "EXTENSION_SCAN"
    URL_SHORTENER = "URL_SHORTENER"
    NON_SCANNABLE = "NON_SCANNABLE"


class ProxySettings(BaseModel):
    server: str = Field(min_length=1)
    username: str | None = None
    password: SecretStr | None = None
    bypass: str | None = None

    @field_validator("server")
    @classmethod
    def validate_server(cls, value: str) -> str:
        value = value.strip()
        allowed = ("http://", "https://", "socks5://")
        if not value.lower().startswith(allowed):
            raise ValueError("proxy server must use http, https or socks5")
        parsed = urlsplit(value)
        if not parsed.hostname:
            raise ValueError("proxy server must contain a hostname")
        if parsed.username or parsed.password:
            raise ValueError("put proxy credentials in username and password fields")
        return value


class BrowserOptions(BaseModel):
    javascript_enabled: bool = True
    capture_screenshot: bool = True
    capture_network: bool = True
    wait_until: Literal["commit", "domcontentloaded", "load", "networkidle"] = (
        "domcontentloaded"
    )
    post_load_wait_ms: int = Field(default=750, ge=0, le=10_000)
    viewport_width: int = Field(default=1366, ge=320, le=3840)
    viewport_height: int = Field(default=768, ge=240, le=2160)
    proxy: ProxySettings | None = None


class FetchRequest(BaseModel):
    target: str = Field(min_length=1)
    timeout_seconds: int = Field(default=10, ge=1, le=120)
    ports: list[int] = Field(default_factory=list)
    browser: BrowserOptions = Field(default_factory=BrowserOptions)

    @field_validator("target")
    @classmethod
    def clean_target(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("target cannot be empty")
        return value

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, values: list[int]) -> list[int]:
        invalid = [port for port in values if port < 1 or port > 65535]
        if invalid:
            raise ValueError("ports must be between 1 and 65535")
        return list(dict.fromkeys(values))


class ScanRequest(FetchRequest):
    scan_type: ScanType = ScanType.WEB_OK
    destination_scan_type: ScanType | None = None

    @model_validator(mode="after")
    def validate_destination(self) -> "ScanRequest":
        if self.scan_type == ScanType.URL_SHORTENER:
            if self.destination_scan_type is None:
                raise ValueError("destination_scan_type is required for URL_SHORTENER")
            if self.destination_scan_type == ScanType.URL_SHORTENER:
                raise ValueError("destination_scan_type cannot also be URL_SHORTENER")
        return self


FetcherStatus = Literal["ok", "partial", "failed", "skipped"]


class FetcherResult(BaseModel):
    fetcher: str
    status: FetcherStatus
    elapsed_ms: int
    data: dict[str, Any] | None = None
    error: str | None = None


class ScanResponse(BaseModel):
    scan_id: str
    target: str
    scan_type: ScanType
    status: FetcherStatus
    selected_fetchers: list[str]
    started_at: datetime
    finished_at: datetime
    elapsed_ms: int
    results: dict[str, FetcherResult]
