# Progress

## Summary (2026-09-23)

**Live demo:** https://reeve25.github.io/vulnprio/ (CI rebuilds it on every push to main and weekly, against live KEV/EPSS)

### What works (verified, not assumed)
- **Parsing:** Trivy JSON, Grype JSON, SARIF 2.1.0 and CSV, gzipped or plain. The format is detected from the document's structure. Every malformed input returns a 400, never a 500. Size, nesting, finding-count and CVE-count caps are in place.
- **Enrichment:** CISA KEV (the full catalog), FIRST EPSS (batched 100 per call) and an NVD CVSS fallback. All three share one 15 s deadline and a 24 h in-process cache. Each source fails independently.
- **Scoring:** P1 (in KEV), P2 (EPSS ≥ 10%), P3 (EPSS ≥ 1% or CVSS ≥ 9), P4. Within a tier: fixable first, then EPSS, then CVSS. Every finding gets a human-readable `reasons[]`.
- **API:** FastAPI, storing to DynamoDB (single table, cursor pagination) and S3 (raw uploads). JSON logs carry request ids, metrics are written as EMF, and responses send a strict CSP.
- **CLI:** `analyze`, `gate` (the CI gate, with expiring waivers; it fails closed when KEV/EPSS are unreachable) and `push` (SigV4).
- **Dashboard:** static on Pages; live mode under `/ui/` supports uploads.
- **Terraform:**
  - Covers Lambda (container image with Lambda Web Adapter), HTTP API with IAM auth, DynamoDB, S3, KMS, ECR, CloudWatch alarms and dashboard, and a GitHub OIDC deploy role.
  - Checked in CI with `validate`, a mocked `terraform test` that asserts least-privilege IAM, and checkov (117 passed, 0 failed).
  - **Never applied.**
- **CI:**
  - Five green jobs: lint + unit tests, LocalStack integration, terraform, an image scan gated by vulnprio itself, and a gitleaks full-history scan.
  - A separate Pages workflow.
  - Actions are pinned to SHAs and images to digests.

### Run it locally (3 commands)
```sh
git clone https://github.com/reeve25/vulnprio && cd vulnprio
docker compose up --build --wait
curl --data-binary @samples/trivy_solr_8.11.0.json.gz "localhost:8080/scans?name=solr"
```
Then open http://localhost:8080/ui/.

### Resume bullet (every number is from this repo)
> Built **vulnprio**, a vulnerability-prioritization service (Python/FastAPI, DynamoDB, S3, Lambda, Terraform) that re-ranks Trivy/Grype/SARIF findings using CISA KEV and FIRST EPSS exploit data. Across 4 public container images it cut the "fix now" queue from **883 HIGH/CRITICAL findings to 140 (84% fewer)** while still surfacing actively exploited bugs that severity rated MEDIUM. It also ships as a CI gate that blocks its own image build, backed by 61 unit and 2 LocalStack integration tests (90% coverage), least-privilege IAM asserted in `terraform test`, and SLOs with alarms.

Be honest in interviews: the AWS stack is designed, validated and cost-estimated (about $4.75/month idle), but **never deployed**. The SLO numbers are targets, not measurements.

### What to learn to defend it
| Topic | Know this | Files |
|---|---|---|
| EPSS / KEV / CVSS | What each measures. EPSS v3 paper: CVSS ≥ 7 gives 3.9% efficiency, EPSS ≥ 0.088 gives 45.5%. Why not multiply EPSS × CVSS. | `docs/RESEARCH.md`, README "Why this scoring model", `scoring.py` |
| Tiers vs. a blended score | Explainability, and preserving what each signal means | DECISIONS #2, `scoring.py` |
| DynamoDB modeling | Single table, why the sort key embeds the tier, `begins_with` + `Limit` + `LastEvaluatedKey` cursors, cursor tamper checks, TTL | `store.py`, DECISIONS #4, #5, #16 |
| Serverless limits | API Gateway's 30 s / Lambda's 6 MB limits, the 15 s enrichment deadline, reserved concurrency, cold vs. warm cache, Lambda Web Adapter | `api.py`, `enrich.py`, `infra/lambda.tf`, DECISIONS #3, #14 |
| AWS auth | SigV4 / IAM auth on HTTP API, GitHub OIDC trust with a pinned `sub`, why there are no API keys | `cli.py` (`push`), `infra/github_oidc.tf`, `infra/apigw.tf`, DECISIONS #15 |
| IAM / KMS | Least-privilege actions and resources, KMS key policy and encryption context for logs | `infra/lambda.tf`, `infra/kms.tf`, `infra/tests/iam.tftest.hcl` |
| IaC testing | `terraform test` with `mock_provider` and `override_during`; checkov and why each suppression is there | `infra/tests/`, `#checkov:skip` comments |
| Untrusted input | Decompression bombs, recursion depth, schema-shape errors → 400, bounded regex, caps against outbound amplification | `parsers.py`, `tests/test_parsers.py` |
| Observability / SRE | SLI vs. SLO, error budgets, why enrichment completeness is its own SLI, EMF, alarm design for bursty traffic, burn-rate alerts as the next step | `docs/SLO.md`, `obs.py`, `infra/monitoring.tf` |
| Supply chain / CI | SHA and digest pinning, fail-closed gates, expiring waivers, least-privilege workflow permissions | `.github/workflows/`, `cli.py` (`gate`) |

### Next 5 steps
1. **Deploy for real** behind an AWS Budgets alarm, then measure the SLOs instead of asserting them.
2. **Async ingest:** presigned S3 upload → S3 event → SQS → worker. This removes the 4 MB / 30 s ceiling and the enrichment deadline.
3. **Reachability:** down-rank vulnerable packages that are installed but never loaded (language call graphs or runtime SBOM diffing).
4. **Asset context:** weight tiers by exposure and data sensitivity (SSVC-style inputs).
5. **Trend view:** per-image P1/P2 burn-down and time-to-remediate. Then replace the static alarms with multi-window burn-rate alerts.

## Log
- 2026-09-23 — Plan: wrote SPEC.md and DECISIONS.md, then had a review subagent critique them from a senior-infra and a recruiter angle. Revisions:
  - 4 MB sync upload cap
  - priority in the sort key
  - SigV4 clients
  - waivers
  - LocalStack pinned to 4.14 (latest needs a token; verified)
  - checkov only
  - terraform test
- 2026-09-23 — Samples: real Trivy (JSON + SARIF) and Grype scans of the public images python:3.9-slim-bullseye, node:16-bullseye-slim, nginx:1.21 and solr:8.11.0, stored gzipped.
- 2026-09-23 — Slice 1, parsers: Trivy/Grype/SARIF/CSV + gzip, GHSA→CVE aliasing, dedup. 18 tests.
- 2026-09-23 — Slices 2–4: enrichment (KEV/EPSS/NVD with mocked-feed tests), scoring tiers with reasons, and the FastAPI service with DynamoDB/S3 storage and EMF metrics.
- 2026-09-23 — Slice 5, docker compose + LocalStack: the init script creates the table and bucket; the integration tests round-trip 880 findings, pagination and a tampered cursor.
- 2026-09-23 — Slice 6, CLI: `analyze`, `gate` (expiring waivers) and `push` (SigV4).
- 2026-09-23 — Slice 7, dashboard: one static page with two modes (the Pages demo reads precomputed JSON; live mode under /ui/ supports upload). Rendering uses textContent only, under a strict CSP. Screenshot in docs/dashboard.png.
- 2026-09-23 — Review of parse/enrich/score (subagent). Fixes:
  - Wrong-shaped JSON, corrupt gzip, oversize CSV fields and deep nesting all returned 500. They now return 400 via one guard in `parse()`.
  - Added finding and CVE caps against memory use and outbound-call amplification.
  - Bounded the CVE regex.
  - SARIF `security-severity` is no longer stored as CVSS. Trivy's value is a per-severity constant: LOW = 2.0 where NVD says 7.5.
  - Trivy output with no `Results` is now accepted.
  - A failed KEV refresh no longer drops the cached catalog.
  - Removed the unused `ttl` parameter.
  - 58 unit tests.
- 2026-09-23 — Slice 8, Terraform (subagent-written, verified). Required version raised to ≥ 1.11 for `override_during` in mocked tests. `terraform test` asserts there are no wildcard IAM actions and that S3 is write-only to `raw/*`.
- 2026-09-23 — Slice 9, CI: 5 jobs. The dogfood gate runs vulnprio against Trivy's scan of its own image (162 findings, 0 act-now, PASS). The gate fails closed if KEV/EPSS are unreachable. The Pages workflow deploys the demo and rebuilds weekly.
- 2026-09-23 — Docs: SLO.md (4 SLIs, error budget policy, alarm → runbook mapping), COST.md, README (live demo link, results table, scoring rationale with citations, walkthrough). Quickstart tested end to end.
- 2026-09-23 — Review of the CI/infra/dashboard/api slices (subagent). Fixes:
  - The cold ingest could outlive the 29 s Lambda timeout (30 sequential EPSS calls). All three feeds now share one 15 s deadline with 5 s per-call timeouts.
  - NVD 429s were counted in the enrichment SLI metric and broke the weekly Pages rebuild. `exploit_data_errors()` now excludes them in one place.
  - A typo in `--fail-on` turned the gate into a no-op. Unknown tiers are now rejected.
  - A blocking ingest stalled `/healthz` under uvicorn. Ingest now runs in a threadpool; verified `/healthz` answers in 98 ms during an ingest.
  - The enrichment alarm could never fire at CI traffic levels. It now uses a 1 h window.
  - Container images are pinned by digest.
  - Removed dead code (`Store.ping`, the `DescribeTable` grant, unused CSS).
  - 61 unit + 2 integration tests; terraform test passes.
