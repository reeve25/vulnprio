# Service level objectives

vulnprio is an internal-facing API: CI pipelines push scans to it, and people look at the results. The SLOs below are
written for that audience. A CI job that can't ingest a scan is blocked. A dashboard that loads slowly is only an annoyance.
The targets were set before deployment. They were then checked against one real deployment (below). That deployment was
torn down afterwards, so nothing is running now (DECISIONS #9).

## Measured on 2026-09-24

The stack was deployed to us-west-2 from `infra/` (Lambda at 1 GB, x86). It was then driven by `scripts/load_test.py`
from one home-internet client (in California), and the stack was destroyed afterwards. In total: 343 API requests,
16 ingests of the 6 `samples/` scans (4,060 findings checked end to end), 300 paced reads at about 5 rps, and 5 cold
starts. This was a latency check, not a load test: peak concurrency was 1.

| What | Result | Source |
|---|---|---|
| Read latency, API Gateway (server) | p50 **24–45 ms**, p95 **32–121 ms**, p99 **≤ 126 ms** by route; the findings page (up to 500 items) is the slowest | API access log `latency`, Logs Insights |
| Read latency, client (includes internet RTT) | p50 **68 ms**, p95 **97 ms**, p99 **116 ms** (n = 300) | `load_test.py` |
| Cold start (Lambda init) | p50 **1.9 s**, range 1.6–2.6 s. The very first init after deploy took **7.8 s** (image not yet cached) | `REPORT` `Init Duration`, n = 5 |
| Cold `/healthz`, client | 2.1–2.7 s (forced by config updates); 8.3 s on first-ever invoke | curl |
| Ingest, small scan (379 findings, 177 KB gz) | warm p50 **383 ms**, max 558 ms | client, 5 runs |
| Ingest, large scan (1,072 findings, 640 KB gz) | warm p50 **863 ms**, max 916 ms | client, 5 runs |
| Ingest, cold feeds (first scan: KEV download + EPSS) | **3.1 s** server / 3.3 s client (880 findings) | `IngestDuration` max |
| Ingest, all 16 (server) | p50 **619 ms**, p95 **3.07 s** | `vulnprio/IngestDuration` |
| Errors | 0 5xx, 0 Lambda errors, 0 throttles, 0 enrichment errors; the only 4xx were 2 deliberate 400s and 2 unsigned 403s | CloudWatch |
| Memory | max 103 MB of 1,024 MB | `REPORT` |

Against the targets: SLI 2 (ingest < 10 s) held with 3× headroom even with cold feeds. SLI 3 (reads < 500 ms p99) held
at about 4× headroom. SLIs 1 and 4 saw no failures, but 343 requests can't prove 99.5%, so they remain targets.
Memory use (103 MB) suggests 512 MB would be enough. That isn't tuned yet, because CPU scales with memory and the
cold start would likely get slower. Dashboard: [`docs/screenshots/cloudwatch-dashboard.png`](screenshots/cloudwatch-dashboard.png).

## SLIs and targets

| # | SLI | Measured from | Target (28-day window) | Why this number |
|---|-----|---------------|------------------------|-----------------|
| 1 | **Availability**: share of API requests that don't return 5xx | `AWS/ApiGateway` `5xx` ÷ `Count` | **99.5%** | CI retries once, so an occasional failure is fine. That leaves ~3.4 h of budget per 28 days. 99.9% would need multi-region, which this doesn't justify. |
| 2 | **Ingest latency**: `POST /scans` completes in < 10 s | `vulnprio/IngestDuration` p99 | **99%** of ingests | API Gateway's hard 30 s limit sets the ceiling. A cold ingest with nothing cached (KEV + up to 30 EPSS batches + up to 5 NVD calls) is the worst case. One shared 15 s enrichment deadline with 5 s per-call timeouts keeps it under the 29 s Lambda timeout; anything unfinished is recorded as an enrichment error instead of timing out. Warm Lambdas cache feeds for 24 h, so a typical run takes about 1 s. |
| 3 | **Read latency**: `GET` endpoints complete in < 500 ms | `AWS/ApiGateway` `Latency` p99 | **99%** of reads | These are single-partition DynamoDB queries. Anything slower points to cold starts or oversized pages. |
| 4 | **Enrichment completeness**: ingests with KEV and EPSS both applied | `vulnprio/EnrichmentErrors` = 0 | **99%** of ingests | A scan ranked without KEV/EPSS still returns 201, so it "succeeds", but it's the worst failure mode: every finding falls to P3/P4 and looks safe. It gets its own SLI so HTTP success can't hide it. |

Not SLOs: NVD CVSS backfill. It's rate-limited to 5 requests per 30 s without a key, and it only affects P3, so a
miss is logged but doesn't count against the budget. The CI gate treats missing NVD data the same way; missing
KEV/EPSS fails the gate closed.

## Error budget policy

- **Budget remaining > 50%**: ship freely.
- **Budget remaining 0–50%**: changes to ingest/enrichment need a LocalStack integration run and a canary (Lambda alias
  weighted routing) before they take full traffic.
- **Budget exhausted**: freeze feature work on the ingest path. The next change must be a reliability fix or a rollback.
  Freezing this path is the lever that matters. Reads come straight from DynamoDB and rarely fail on their own.

## Alarms → SLOs

Alarms page on symptoms that burn budget. They don't page on every error. Every alarm uses
`treat_missing_data = notBreaching`, so an idle service stays quiet.

| Alarm (`infra/monitoring.tf`) | Condition | Protects | First thing to check |
|-------------------------------|-----------|----------|----------------------|
| `vulnprio-api-5xx-rate` | > 1% 5xx over 15 min | SLI 1 | Lambda logs filtered by `level=ERROR`. Correlate with `x-request-id`. |
| `vulnprio-lambda-errors` | ≥ 1 invocation error in 5 min | SLI 1 | Timeouts, OOM and crashes. App exceptions don't land here: Lambda Web Adapter turns them into HTTP 500s, which the 5xx-rate alarm catches. |
| `vulnprio-lambda-throttles` | ≥ 1 throttle in 5 min | SLI 1 | Reserved concurrency (`infra/lambda.tf`) vs. a CI burst. |
| `vulnprio-ingest-p99` | p99 `IngestDuration` > 20 s | SLI 2 | Leaves 10 s of headroom before the hard 30 s timeout. Usually a slow upstream feed. |
| `vulnprio-enrichment-errors` | ≥ 2 KEV/EPSS misses in 1 h | SLI 4 | Upstream outage (CISA/FIRST status). A single flaky call won't page; a second miss in the same hour will, even at low CI traffic. |

A 14.4× fast-burn / 1× slow-burn multi-window alert pair (Google SRE workbook ch. 5) is the next step up from these
static thresholds. It isn't worth it before there's real traffic to tune against.

## Where the signals come from

- **Metrics**: API Gateway and Lambda built-ins, plus app metrics written as CloudWatch Embedded Metric Format lines
  (`src/vulnprio/obs.py`). No agent or `PutMetricData` call is needed, because CloudWatch extracts them from the logs.
- **Logs**: one JSON line per request (`method`, `path`, `status`, `duration_ms`, `request_id`) and one per ingest
  (scan id, format, summary counts). Retention is 30 days. Logs are KMS-encrypted.
- **Dashboard**: `aws_cloudwatch_dashboard.this` shows requests and 5xx, latency p50/p99, Lambda health,
  findings ingested vs. act-now, and enrichment errors.
