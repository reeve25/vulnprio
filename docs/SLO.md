# Service level objectives

vulnprio is an internal-facing API: CI pipelines push scans to it, and people look at the results. The SLOs below are
written for that audience. A CI job that can't ingest a scan is blocked. A dashboard that loads slowly is only an annoyance.
The numbers are targets for the Terraform design in `infra/`. They have **not** been measured in production, because
nothing is deployed (DECISIONS #9).

## SLIs and targets

| # | SLI | Measured from | Target (28-day window) | Why this number |
|---|-----|---------------|------------------------|-----------------|
| 1 | **Availability**: share of API requests that don't return 5xx | `AWS/ApiGateway` `5xx` ÷ `Count` | **99.5%** | CI retries once, so an occasional failure is fine. That leaves ~3.4 h of budget per 28 days. 99.9% would need multi-region, which this doesn't justify. |
| 2 | **Ingest latency**: `POST /scans` completes in < 10 s | `vulnprio/IngestDuration` p99 | **99%** of ingests | API Gateway's hard 30 s limit sets the ceiling. A cold ingest with nothing cached (KEV + 7 EPSS batches + up to 5 NVD calls) is the worst case. Warm Lambdas cache feeds for 24 h, so a typical run takes about 1 s. |
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
| `vulnprio-lambda-errors` | ≥ 1 unhandled error in 5 min | SLI 1 | Unhandled exceptions are bugs. Malformed input is a 400 by design, not a 500. |
| `vulnprio-lambda-throttles` | ≥ 1 throttle in 5 min | SLI 1 | Reserved concurrency (`infra/lambda.tf`) vs. a CI burst. |
| `vulnprio-ingest-p99` | p99 `IngestDuration` > 20 s | SLI 2 | Leaves 10 s of headroom before the hard 30 s timeout. Usually a slow upstream feed. |
| `vulnprio-enrichment-errors` | errors in 3 consecutive 15-min periods | SLI 4 | Upstream outage (CISA/FIRST status). A single flaky call won't page. A sustained outage will. |

A 14.4× fast-burn / 1× slow-burn multi-window alert pair (Google SRE workbook ch. 5) is the next step up from these
static thresholds. It isn't worth it before there's real traffic to tune against.

## Where the signals come from

- **Metrics**: API Gateway and Lambda built-ins, plus app metrics written as CloudWatch Embedded Metric Format lines
  (`src/vulnprio/obs.py`). No agent or `PutMetricData` call is needed, because CloudWatch extracts them from the logs.
- **Logs**: one JSON line per request (`method`, `path`, `status`, `duration_ms`, `request_id`) and one per ingest
  (scan id, format, summary counts). Retention is 30 days. Logs are KMS-encrypted.
- **Dashboard**: `aws_cloudwatch_dashboard.this` shows requests and 5xx, latency p50/p99, Lambda health,
  findings ingested vs. act-now, and enrichment errors.
