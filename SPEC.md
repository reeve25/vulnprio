# vulnprio — spec

**One line:** ingest scanner output, enrich every CVE with real-world exploit data (CISA KEV, FIRST EPSS, NVD CVSS), and rank findings by likelihood of exploitation instead of raw severity.

**Problem:** a typical container scan returns hundreds of "HIGH/CRITICAL" findings. CVSS measures *how bad if exploited*, not *how likely to be exploited*. Only a few percent of published CVEs are ever exploited in the wild, so severity-only triage wastes most remediation effort. vulnprio puts the known-exploited and likely-exploited findings at the top and explains why.

## Scope (v1)

### Inputs
| Format | Source | Detection |
|---|---|---|
| Trivy JSON | `trivy image -f json` | top-level `Results` + `SchemaVersion` |
| Grype JSON | `grype -o json` | top-level `matches` |
| SARIF 2.1.0 | Trivy/Grype/any SARIF emitter | top-level `runs` |
| CSV | generic export | header row with at least `cve` (case-insensitive); optional `package, version, fixed_version, severity, cvss, target` |

Uploads are untrusted input: body ≤ 4 MB (API Gateway base64-encodes bodies and Lambda's sync payload cap is 6 MB), gzip bodies accepted and capped at 50 MB decompressed (zip-bomb guard), strict parsing, unknown format → 400. Grype GHSA matches are mapped to their CVE alias via `relatedVulnerabilities`.

### Normalized finding
`vuln_id, cve (nullable), package, installed_version, fixed_version, severity, cvss, target, source_format` +
enrichment `kev (bool), kev_date_added, kev_ransomware, epss, epss_percentile, epss_date` +
scoring `priority (P1–P4), reasons[]`.

### Enrichment
- **KEV:** download the full CISA catalog JSON once, cache in-process 24 h.
- **EPSS:** FIRST API, batched (≤100 CVEs/request), cache in-process 24 h.
- **NVD:** only for findings whose scanner gave no CVSS; max 5 lookups per scan (public API allows 5 req / 30 s without a key), stops on 403/429. Keeps ingest inside API Gateway's 30 s hard timeout.
- Enrichment failure never fails an ingest: the finding is scored on what is known and the reason list says what was missing. Emits an `EnrichmentErrors` metric.

### Scoring (transparent tiers, not a black-box number)
| Priority | Rule | Meaning |
|---|---|---|
| P1 Act now | CVE is in CISA KEV | exploited in the wild (a key input to CISA BOD 26-04 deadlines) |
| P2 Urgent | EPSS ≥ 0.10 | high probability of exploitation in next 30 days |
| P3 Scheduled | EPSS ≥ 0.01 **or** CVSS ≥ 9.0 | plausible exploitation or catastrophic impact |
| P4 Backlog | everything else | |

Within a tier: sort by fix available, EPSS, CVSS (all descending). Each finding carries human-readable `reasons`.
Headline metric per scan: *"N findings, X rated HIGH/CRITICAL by CVSS, Y are P1/P2."*

### API (FastAPI)
| Method | Path | Purpose |
|---|---|---|
| POST | `/scans?name=` | upload raw scanner output (format auto-detected); stores raw file in S3, findings in DynamoDB; returns scan summary |
| GET | `/scans` | list scans (newest first) |
| GET | `/scans/{id}` | scan summary |
| GET | `/scans/{id}/findings?priority=&limit=&cursor=` | ranked findings, paginated (opaque cursor) |
| GET | `/healthz` | liveness |
| GET | `/ui/` | dashboard, **local dev only** (same page as the public demo) |

Who calls the API in AWS: CI pipelines via `vulnprio push`, signing requests with SigV4 (botocore, already a dependency). Browsers can't sign SigV4, so the hosted UI is the static Pages demo.

### Storage
- **S3:** raw uploads (`raw/{scan_id}`), SSE, versioning, public access blocked, 90-day lifecycle.
- **DynamoDB (single table, on-demand):** `PK=SCAN#{id}` / `SK=META` or `SK=F#{priority}#{rank:05d}` (priority filter = `begins_with` key condition, so pagination stays correct); scan index item `PK=SCANS`, `SK={created_at}#{id}`. Findings are written first, META + index last, so a failed ingest is never listed. TTL 90 days, matching the S3 lifecycle.

### AWS (Terraform, validated only — never applied to a real account)
API Gateway HTTP API (IAM auth) → Lambda (container image, AWS Lambda Web Adapter) → DynamoDB + S3. ECR for the image. Least-privilege IAM (per-table, per-bucket-prefix actions). CloudWatch: EMF metrics, alarms (Lambda errors, 5xx rate, enrichment errors; `notBreaching` on missing data so a quiet service doesn't page), dashboard. One KMS CMK for S3/DynamoDB/logs. GitHub OIDC role (no long-lived keys) scoped to this repo's `main` for ECR push. `terraform test` with a mocked provider asserts least-privilege and public-access-block invariants. Cost estimate in `docs/COST.md`.

### Local
`docker compose up` → API + LocalStack (S3, DynamoDB). Same container image as Lambda.

### Observability
JSON structured logs (one line per request/scan with request id), CloudWatch Embedded Metric Format for metrics (no SDK calls, no extra latency), SLOs in `docs/SLO.md`.

### Demo
GitHub Pages static dashboard built by CI from real Trivy/Grype scans of public, outdated images in `samples/`, re-enriched on every push to main and weekly. Page shows "data as of" so staleness is visible. Untrusted strings rendered only via `textContent`, strict CSP.

### CI (GitHub Actions)
ruff lint+format, pytest unit (coverage gate), LocalStack integration tests (image pinned to `4.14`, the last tag that runs without an auth token), terraform fmt/validate/test, checkov (IaC), container build + Trivy image scan **gated by vulnprio itself** (dogfooding: fail on P1/P2 with a fix available; time-boxed waivers in `.vulnprio-waivers`, expired waiver = failure), gitleaks secret scan, Pages deploy.

## Non-goals (v1)
Async ingest (upgrade path: presigned S3 PUT → S3 event → worker Lambda); auth/multi-tenancy beyond API Gateway IAM auth; asset criticality / exposure / reachability context (BOD 26-04 weighs exposure; the tiers don't); SBOM ingestion; dedup across scans; UI editing/ticketing.
