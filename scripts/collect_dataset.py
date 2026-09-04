#!/usr/bin/env python3
"""Collect a small research dataset through the local demonstration API."""

from __future__ import annotations

import argparse
import csv
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import requests


def utc_text() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_ports(value: str) -> list[int]:
    """Parse values such as '22;80;443;8000-8003'."""
    ports: list[int] = []
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"invalid port range: {part}")
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))

    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise ValueError("ports must be between 1 and 65535")
    return list(dict.fromkeys(ports))


def collect_dataset(
    input_csv: Path,
    output_dir: Path,
    api_url: str,
    delay_seconds: float = 1.0,
    request_timeout: int = 130,
    session: requests.Session | None = None,
) -> dict:
    started_at = utc_text()
    client = session or requests.Session()
    output_dir.mkdir(parents=True, exist_ok=True)
    records_path = output_dir / "records.jsonl"
    index_path = output_dir / "index.csv"

    with input_csv.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    index_rows: list[dict[str, object]] = []
    succeeded = 0
    failed = 0

    with records_path.open("w", encoding="utf-8") as records_file:
        for position, row in enumerate(rows):
            sample_id = str(uuid4())
            target = (row.get("target") or "").strip()
            scan_type = (row.get("scan_type") or "WEB_OK").strip()
            payload: dict[str, object] = {
                "target": target,
                "scan_type": scan_type,
            }
            collected_at = utc_text()
            started = time.perf_counter()
            try:
                payload["ports"] = parse_ports(row.get("ports") or "")
                destination_scan_type = (row.get("destination_scan_type") or "").strip()
                if destination_scan_type:
                    payload["destination_scan_type"] = destination_scan_type
                response = client.post(
                    f"{api_url.rstrip('/')}/scan",
                    json=payload,
                    timeout=request_timeout,
                )
                response.raise_for_status()
                scan = response.json()
                request_status = "success"
                error = ""
                succeeded += 1
            except (requests.RequestException, ValueError) as exc:
                scan = None
                request_status = "failed"
                error = str(exc)
                failed += 1

            elapsed_ms = round((time.perf_counter() - started) * 1000)
            record = {
                "sample_id": sample_id,
                "dataset_label": (row.get("label") or "").strip(),
                "collected_at": collected_at,
                "request": payload,
                "request_status": request_status,
                "request_error": error or None,
                "scan": scan,
            }
            records_file.write(json.dumps(record, ensure_ascii=False) + "\n")
            records_file.flush()

            results = scan.get("results", {}) if scan else {}
            successful_fetchers = sorted(
                name for name, result in results.items() if result.get("status") == "ok"
            )
            failed_fetchers = sorted(
                name for name, result in results.items() if result.get("status") == "failed"
            )
            index_rows.append(
                {
                    "sample_id": sample_id,
                    "target": target,
                    "label": (row.get("label") or "").strip(),
                    "scan_type": scan_type,
                    "request_status": request_status,
                    "scan_status": scan.get("status", "") if scan else "",
                    "elapsed_ms": elapsed_ms,
                    "successful_fetchers": ";".join(successful_fetchers),
                    "failed_fetchers": ";".join(failed_fetchers),
                    "collected_at": collected_at,
                    "error": error,
                }
            )

            if delay_seconds > 0 and position < len(rows) - 1:
                time.sleep(delay_seconds)

    fieldnames = list(index_rows[0]) if index_rows else [
        "sample_id",
        "target",
        "label",
        "scan_type",
        "request_status",
        "scan_status",
        "elapsed_ms",
        "successful_fetchers",
        "failed_fetchers",
        "collected_at",
        "error",
    ]
    with index_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(index_rows)

    metadata = {
        "started_at": started_at,
        "finished_at": utc_text(),
        "input_csv": str(input_csv.resolve()),
        "api_url": api_url,
        "delay_seconds": delay_seconds,
        "total_samples": len(rows),
        "successful_requests": succeeded,
        "failed_requests": failed,
        "files": {"records": records_path.name, "index": index_path.name},
    }
    (output_dir / "run_metadata.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return metadata


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_csv", type=Path, help="CSV with target, scan_type, ports and label columns")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between samples in seconds")
    parser.add_argument("--request-timeout", type=int, default=130)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output_dir or Path("runs") / timestamp
    metadata = collect_dataset(
        args.input_csv,
        output_dir,
        args.api_url,
        args.delay,
        args.request_timeout,
    )
    print(f"Collected {metadata['total_samples']} samples in {output_dir.resolve()}")


if __name__ == "__main__":
    main()
