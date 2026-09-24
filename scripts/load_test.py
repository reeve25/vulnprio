"""End-to-end check + latency measurement against a deployed vulnprio API (SigV4, like `vulnprio push`).

    uv run python scripts/load_test.py https://<api-id>.execute-api.us-west-2.amazonaws.com

Asserts correctness first (every sample ingests, pagination returns every finding in rank order, priority filter,
auth and bad-input handling), then prints client-side latency percentiles as JSON. Stays under the stage
throttle (10 rps / burst 20) so it measures latency, not throttling.
"""

import gzip
import json
import statistics
import sys
import time
from pathlib import Path

import boto3
import httpx
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

API = sys.argv[1].rstrip("/")
SAMPLES = Path(__file__).resolve().parent.parent / "samples"
session = boto3.Session()
creds, region = session.get_credentials(), session.region_name
client = httpx.Client(timeout=35)


def call(method, path, body=b"", params=None, sign=True):
    url = str(httpx.URL(API + path, params=params or {}))
    req = AWSRequest(method=method, url=url, data=body)
    if sign:
        SigV4Auth(creds, "execute-api", region).add_auth(req)
    start = time.perf_counter()
    resp = client.request(method, url, content=body, headers=dict(req.headers))
    return resp, (time.perf_counter() - start) * 1000


def pct(xs, p):
    return round(statistics.quantiles(xs, n=100, method="inclusive")[p - 1], 1)


def all_findings(scan_id):
    out, cursor = [], None
    while True:
        params = {"limit": 500, **({"cursor": cursor} if cursor else {})}
        r, _ = call("GET", f"/scans/{scan_id}/findings", params=params)
        assert r.status_code == 200, r.text
        out += r.json()["findings"]
        if not (cursor := r.json()["next"]):
            return out


results = {}
r, ms = call("GET", "/healthz", sign=False)
assert r.status_code == 200, r.text
results["first_request_ms"] = round(ms, 1)  # includes cold start if the function was idle

# Auth: data routes reject unsigned callers.
assert call("GET", "/scans", sign=False)[0].status_code == 403
assert call("POST", "/scans", b"{}", sign=False)[0].status_code == 403
# Hostile/malformed input is a 400, not a 500.
assert call("POST", "/scans", b'{"nope": 1}')[0].status_code == 400
assert call("POST", "/scans", b"\x1f\x8b garbage")[0].status_code == 400

# Ingest every sample and verify what comes back.
ingest = {}
for f in sorted(SAMPLES.glob("*.gz")):
    r, ms = call("POST", "/scans", f.read_bytes(), params={"name": f.name})
    assert r.status_code == 201, (f.name, r.status_code, r.text)
    meta = r.json()
    s = meta["summary"]
    assert not [e for e in meta["enrichment_errors"] if "NVD" not in e], meta["enrichment_errors"]
    findings = all_findings(meta["scan_id"])
    assert len(findings) == s["total"], (f.name, len(findings), s["total"])
    order = [x["priority"] for x in findings]
    assert order == sorted(order), f"{f.name}: findings not in priority order"
    p1 = call("GET", f"/scans/{meta['scan_id']}/findings", params={"priority": "P1", "limit": 500})[0].json()
    assert all(x["priority"] == "P1" for x in p1["findings"]) and len(p1["findings"]) == order.count("P1")
    raw_bytes = len(gzip.decompress(f.read_bytes()))
    ingest[f.name] = {"ms": round(ms), "bytes": f.stat().st_size, "raw_bytes": raw_bytes, **s}
results["ingest_first_pass"] = ingest
listed = {x["name"] for x in call("GET", "/scans")[0].json()["scans"]}
assert set(ingest) <= listed, "an ingested scan is missing from GET /scans"
print(f"e2e OK: {len(ingest)} scans, {sum(v['total'] for v in ingest.values())} findings verified", file=sys.stderr)

# Warm ingest: smallest vs largest sample by finding count, 5 runs each.
by_size = sorted(ingest, key=lambda k: ingest[k]["total"])
for label, name in (("small", by_size[0]), ("large", by_size[-1])):
    body = (SAMPLES / name).read_bytes()
    times = [call("POST", "/scans", body, params={"name": f"bench-{label}"})[1] for _ in range(5)]
    results[f"ingest_warm_{label}"] = {
        "file": name,
        "findings": ingest[name]["total"],
        "p50_ms": round(statistics.median(times)),
        "max_ms": round(max(times)),
    }

# Read latency: 300 signed GETs across the read routes, paced to ~5 rps.
scan_id = call("GET", "/scans")[0].json()["scans"][0]["scan_id"]
paths = ["/scans", f"/scans/{scan_id}", f"/scans/{scan_id}/findings"]
reads = []
for i in range(300):
    r, ms = call("GET", paths[i % 3])
    assert r.status_code == 200, r.text
    reads.append(ms)
    time.sleep(max(0, 0.2 - ms / 1000))
results["read_latency_ms"] = {"n": len(reads), "p50": pct(reads, 50), "p95": pct(reads, 95), "p99": pct(reads, 99)}
print(json.dumps(results, indent=2))
