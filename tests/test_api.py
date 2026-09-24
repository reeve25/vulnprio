import gzip
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vulnprio import api
from vulnprio.store import _cursor_decode, _cursor_encode

SAMPLES = Path(__file__).parent.parent / "samples"


class MemStore:
    """In-memory stand-in with the same interface as Store (real Store is covered by integration tests)."""

    def __init__(self):
        self.scans, self.findings, self.raw = {}, {}, {}

    def save_scan(self, meta, findings, raw):
        from dataclasses import asdict

        self.scans[meta["scan_id"]] = meta
        self.findings[meta["scan_id"]] = [asdict(f) for f in findings]
        self.raw[meta["scan_id"]] = raw

    def list_scans(self, limit=50):
        return sorted(self.scans.values(), key=lambda m: m["created_at"], reverse=True)[:limit]

    def get_scan(self, scan_id):
        return self.scans.get(scan_id)

    def get_findings(self, scan_id, priority=None, limit=100, cursor=None):
        rows = [f for f in self.findings[scan_id] if priority in (None, f["priority"])]
        start = int(cursor or 0)
        nxt = str(start + limit) if start + limit < len(rows) else None
        return rows[start : start + limit], nxt


class FakeEnricher:
    kev_version = "test"

    def enrich(self, findings):
        for f in findings:
            if f.cve == "CVE-2023-4863":
                f.kev = True
            if f.cve == "CVE-2023-44487":
                f.epss = 0.9
        return []


@pytest.fixture
def client():
    store = MemStore()
    api.app.dependency_overrides[api.get_store] = lambda: store
    api.app.dependency_overrides[api.get_enricher] = FakeEnricher
    yield TestClient(api.app)
    api.app.dependency_overrides.clear()


def test_ingest_list_and_page_findings(client):
    body = (SAMPLES / "trivy_nginx_1.21.json.gz").read_bytes()
    r = client.post("/scans?name=nginx", content=body)
    assert r.status_code == 201, r.text
    meta = r.json()
    assert meta["name"] == "nginx"
    assert meta["format"] == "trivy"
    assert meta["summary"]["by_priority"]["P1"] >= 1
    assert r.headers["content-security-policy"].startswith("default-src 'self'")
    assert r.headers["x-request-id"]

    assert client.get("/scans").json()["scans"][0]["scan_id"] == meta["scan_id"]
    assert client.get(f"/scans/{meta['scan_id']}").json() == meta

    page = client.get(f"/scans/{meta['scan_id']}/findings?limit=5").json()
    assert len(page["findings"]) == 5
    assert page["findings"][0]["priority"] == "P1"
    assert page["next"]

    p2 = client.get(f"/scans/{meta['scan_id']}/findings?priority=P2").json()["findings"]
    assert p2 and all(f["priority"] == "P2" for f in p2)


def test_bad_input_is_400_not_500(client):
    r = client.post("/scans", content=b'{"not": "a scan"}')
    assert r.status_code == 400
    assert "unrecognised" in r.json()["detail"]


def test_oversized_body_rejected(client, monkeypatch):
    monkeypatch.setattr(api, "MAX_BODY", 100)
    r = client.post("/scans", content=gzip.compress(json.dumps({"x": "y" * 1000}).encode() * 10) + b"x" * 200)
    assert r.status_code == 413


def test_validation_and_404s(client):
    assert client.get("/scans/nope").status_code == 404
    assert client.get("/scans/nope/findings").status_code == 404
    assert client.get("/scans?limit=0").status_code == 422
    assert client.get("/scans/x/findings?priority=P9").status_code == 422
    assert client.get("/healthz").json() == {"ok": True}


def test_ui_is_served(client):
    assert client.get("/ui/").status_code == 200
    assert client.get("/", follow_redirects=False).headers["location"] == "/ui/"


def test_cursor_roundtrip_and_tamper_rejected():
    key = {"PK": "SCAN#abc", "SK": "F#P1#00001"}
    assert _cursor_decode(_cursor_encode(key), "abc") == key
    assert _cursor_decode(None, "abc") is None
    for bad in [
        _cursor_encode({"PK": "SCAN#other", "SK": "F#P1#00001"}),  # another scan's partition
        _cursor_encode({"PK": "SCANS", "SK": "x"}),
        _cursor_encode({"PK": "SCAN#abc", "SK": "META"}),
        "!!!not-base64",
        _cursor_encode({"PK": "SCAN#abc", "SK": "F#P1#1", "extra": 1}),
    ]:
        with pytest.raises(ValueError):
            _cursor_decode(bad, "abc")
