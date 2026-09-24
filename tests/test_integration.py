"""Store + API against real DynamoDB/S3 APIs in LocalStack.

Run: docker compose up -d localstack && uv run pytest -m integration
"""

import os
import uuid
from pathlib import Path

import boto3
import pytest
from fastapi.testclient import TestClient

from vulnprio import api
from vulnprio.store import Store

pytestmark = pytest.mark.integration
ENDPOINT = os.environ.get("LOCALSTACK_URL", "http://localhost:4566")
SAMPLES = Path(__file__).parent.parent / "samples"


class NoNetworkEnricher:
    kev_version = None

    def enrich(self, findings):
        for f in findings:
            f.kev = f.cve == "CVE-2023-4863"
        return []


@pytest.fixture(scope="module")
def store():
    for k, v in {
        "AWS_ACCESS_KEY_ID": "test",
        "AWS_SECRET_ACCESS_KEY": "test",
        "AWS_DEFAULT_REGION": "us-east-1",
    }.items():
        os.environ.setdefault(k, v)
    # A fresh table per run so reruns don't see old data
    name = f"vulnprio-it-{uuid.uuid4().hex[:8]}"
    ddb = boto3.client("dynamodb", endpoint_url=ENDPOINT)
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": a, "AttributeType": "S"} for a in ("PK", "SK")],
        KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}],
        BillingMode="PAY_PER_REQUEST",
    )
    boto3.client("s3", endpoint_url=ENDPOINT).create_bucket(Bucket=name)
    yield Store(table=name, bucket=name, endpoint_url=ENDPOINT)
    ddb.delete_table(TableName=name)


@pytest.fixture(scope="module")
def client(store):
    api.app.dependency_overrides[api.get_store] = lambda: store
    api.app.dependency_overrides[api.get_enricher] = NoNetworkEnricher
    yield TestClient(api.app)
    api.app.dependency_overrides.clear()


def test_full_ingest_roundtrip(client, store):
    body = (SAMPLES / "trivy_nginx_1.21.json.gz").read_bytes()
    meta = client.post("/scans?name=it", content=body).json()
    scan_id = meta["scan_id"]
    total = meta["summary"]["total"]
    assert total > 800  # > 25 items, so batch_writer chunking is exercised

    # raw upload landed in S3 byte-for-byte
    obj = store.s3.get_object(Bucket=store.bucket, Key=f"raw/{scan_id}")
    assert obj["Body"].read() == body

    # page through every finding with the cursor; order and count must survive DynamoDB
    seen, cursor = [], None
    while True:
        params = {"limit": 250, **({"cursor": cursor} if cursor else {})}
        page = client.get(f"/scans/{scan_id}/findings", params=params).json()
        seen += page["findings"]
        if not (cursor := page["next"]):
            break
    assert len(seen) == total
    order = [f["priority"] for f in seen]
    assert order == sorted(order)
    assert seen[0]["kev"] is True

    # priority filter is a key condition, so pages are full and exact
    p1 = client.get(f"/scans/{scan_id}/findings", params={"priority": "P1"}).json()["findings"]
    assert len(p1) == meta["summary"]["by_priority"]["P1"]

    assert client.get("/scans").json()["scans"][0]["scan_id"] == scan_id
    assert client.get(f"/scans/{scan_id}").json()["summary"] == meta["summary"]


def test_tampered_cursor_is_400(client):
    meta = client.post("/scans", content=b"cve\nCVE-2020-0001\n").json()
    r = client.get(f"/scans/{meta['scan_id']}/findings", params={"cursor": "eyJQSyI6ICJTQ0FOUyJ9"})
    assert r.status_code == 400
