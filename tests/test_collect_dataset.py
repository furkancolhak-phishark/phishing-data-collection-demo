import csv
import json

from scripts.collect_dataset import collect_dataset, parse_ports


class FakeAPIResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {
            "status": "ok",
            "results": {
                "dns": {"status": "ok"},
                "tls": {"status": "failed"},
            },
        }


class FakeSession:
    def __init__(self):
        self.payloads = []

    def post(self, url, json, timeout):
        self.payloads.append(json)
        return FakeAPIResponse()


def test_parse_ports_accepts_values_and_ranges():
    assert parse_ports("22;80;8000-8002;22") == [22, 80, 8000, 8001, 8002]


def test_collector_writes_jsonl_csv_and_metadata(tmp_path):
    input_csv = tmp_path / "targets.csv"
    input_csv.write_text(
        "target,scan_type,ports,label\nlocalhost,RESOLVED_NO_WEB,22;80,local\n",
        encoding="utf-8",
    )
    output_dir = tmp_path / "run"
    session = FakeSession()

    metadata = collect_dataset(
        input_csv,
        output_dir,
        "http://127.0.0.1:8000",
        delay_seconds=0,
        session=session,
    )

    assert metadata["total_samples"] == 1
    assert session.payloads[0]["ports"] == [22, 80]
    record = json.loads((output_dir / "records.jsonl").read_text(encoding="utf-8"))
    assert record["dataset_label"] == "local"

    with (output_dir / "index.csv").open(newline="", encoding="utf-8") as handle:
        row = next(csv.DictReader(handle))
    assert row["successful_fetchers"] == "dns"
    assert row["failed_fetchers"] == "tls"
    assert (output_dir / "run_metadata.json").exists()


def test_invalid_ports_fail_only_the_affected_row(tmp_path):
    input_csv = tmp_path / "targets.csv"
    input_csv.write_text(
        "target,scan_type,ports,label\nlocalhost,RESOLVED_NO_WEB,70000,bad\n",
        encoding="utf-8",
    )

    metadata = collect_dataset(
        input_csv,
        tmp_path / "run",
        "http://127.0.0.1:8000",
        delay_seconds=0,
        session=FakeSession(),
    )

    assert metadata["failed_requests"] == 1
    record = json.loads((tmp_path / "run" / "records.jsonl").read_text(encoding="utf-8"))
    assert record["request_status"] == "failed"
