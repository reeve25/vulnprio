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
  - **Applied once** to us-west-2 (2026-09-24), tested end to end, measured, then destroyed (Session 3).
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
> Built **vulnprio**, a vulnerability-prioritization service (Python/FastAPI, DynamoDB, S3, Lambda, Terraform) that re-ranks Trivy/Grype/SARIF findings using CISA KEV and FIRST EPSS exploit data. Across 4 public container images it cut the "fix now" queue from **883 HIGH/CRITICAL findings to 140 (84% fewer)** while still surfacing actively exploited bugs that severity rated MEDIUM. **Deployed and load-tested on AWS, then torn down**: 4,060 findings were verified end to end through API Gateway, with p95 read latency ≤ 121 ms, 0.9 s ingest for a 1,072-finding scan and 0 errors, all measured against the SLOs. It also ships as a CI gate that blocks its own image build, backed by 61 unit and 2 LocalStack integration tests and least-privilege IAM asserted in `terraform test`.

Be honest in interviews: it ran for about 2 hours on one day (2026-09-24), with 343 requests from one client at concurrency 1. "Load-tested" means a latency check, not a stress test. It proves the latency SLOs have headroom, not the 99.5% availability target. It is not running now; it was destroyed on purpose.

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
1. **Run it continuously**: remote S3 state, a CI deploy through the OIDC role, and a quota increase so reserved concurrency (DECISIONS #17) comes back. Then do a real concurrency test.
2. **Async ingest:** presigned S3 upload → S3 event → SQS → worker. This removes the 4 MB / 30 s ceiling and the enrichment deadline.
3. **Reachability:** down-rank vulnerable packages that are installed but never loaded (language call graphs or runtime SBOM diffing).
4. **Asset context:** weight tiers by exposure and data sensitivity (SSVC-style inputs).
5. **Trend view:** per-image P1/P2 burn-down and time-to-remediate. Then replace the static alarms with multi-window burn-rate alerts.

## Session 3 (2026-09-24): deployed, measured, torn down

1. **Deployed to AWS** (us-west-2), behind a $5/month AWS Budget with email alerts. The apply hit one real failure: the new-account reserved-concurrency limit (DECISIONS #17).
2. **End-to-end test passed through API Gateway:** 6 sample scans and 4,060 findings verified (pagination, rank order, P1 filter, SigV4 403s, malformed input → 400). All 5 alarms were OK, a forced alarm published to SNS, and all 5 dashboard widgets were populated.
3. **Measured:** read p50/p95 was 68/97 ms from the client and ≤ 45/121 ms at API Gateway. Cold start p50 was 1.9 s. Ingest p50 was 383 ms for a small scan and 863 ms for a large one, and 3.1 s with cold feeds. 0 errors in 343 requests. Estimated cost at demo traffic is about $6.25/month list, about $1.15 after the free tiers.
4. **Destroyed** (35/35), then verified: nothing tagged `project=vulnprio` remains except the Budget. The KMS key is PendingDeletion until 2026-10-01 and isn't billed.
5. **Resume bullet now says "deployed and load-tested on AWS, then torn down"**, with the caveats listed next to it. Three commits pushed (`5d85cb6`, `cb8f4fd`, `38b151b`). gitleaks is clean, and CI (5/5 jobs) and Pages are green on `38b151b`.

### What was done
- **Access:** `aws sts get-caller-identity` worked with the SSO Admin role. The CLI and Terraform 1.16.2 were installed, but the shell's PATH was stale, so it was reloaded from the registry.
- **Guardrail:** `vulnprio-monthly-5usd` Budget, created with the CLI rather than Terraform so that `destroy` can't remove it. It alerts at 50% and 100% of actual spend and at 100% of forecast, and is tagged `project=vulnprio`.
- **Terraform changes** (all pass `validate`, the mocked `terraform test`, and checkov 117/0):
  - The default region is now `us-west-2`.
  - The default tag is now lowercase `project`. Tag keys are case-sensitive, so the old `Project` tag would have slipped past the teardown check.
  - `var.reserved_concurrency` (DECISIONS #17).
  - `var.allow_destroy` (DECISIONS #18).
  - KMS `deletion_window_in_days = 7`.
- **Apply sequence:**
  1. Targeted apply of the ECR repo and KMS key.
  2. Built and pushed the image as `d988f6c`, with `--provenance=false` because Lambda rejects image indexes.
  3. Full apply, which failed on `PutFunctionConcurrency`.
  4. Re-apply with `reserved_concurrency=-1`, which replaced the tainted function. 35 resources in total.
- **Test:** `scripts/load_test.py` checks correctness first, then measures latency. Cold starts were forced by changing the function description 4 times.
  - Server-side numbers come from Logs Insights (REPORT `Init Duration`, the API access-log `latency`, and the EMF `IngestDuration`).
  - Full table in `docs/SLO.md`.
- **Dashboard screenshot:** `docs/screenshots/cloudwatch-dashboard.png`. These are the 5 deployed widgets rendered with `GetMetricWidgetImage`, because there's no console login in a headless session.
- **Teardown:** `apply -var allow_destroy=true`, then `destroy` (35 destroyed). I checked each service for leftovers:
  - Tagging API in us-west-2 (checked both `project` and `Project`) and in us-east-1/us-east-2/us-west-1: only the Budget and the pending-deletion KMS key remain.
  - Lambda, API Gateway, DynamoDB, RDS, S3, ECR, log groups, alarms, dashboards, SNS, IAM roles, OIDC provider: 0 each.
- Local cleanup: removed the ECR image tag from Docker and ran `docker logout` on the registry. The local `terraform.tfstate` is gitignored and now empty.

### Not done / caveats
- There was no alarm email subscription (`alarm_email` stayed null), so the forced alarm was only confirmed in CloudWatch history, not in an inbox.
- The Budget alert emails don't need confirmation, but check the inbox anyway.
- Concurrency was 1 throughout. No burst or throttle test was run: the 10-rps stage throttle and the 10-execution account quota would dominate.
- The ~$0.05 actual spend is an estimate. Cost Explorer lags about 24 h.

## Session 2 (2026-09-23)

1. **Live demo verified.** Headless Chromium at 1440×900 and 390×844: 5 scans, 1,015 chart points, 100 table rows, no console or network errors.
2. **Fixed a phone layout bug.** Table columns were crushed to one character wide. Pushed the fix; CI and Pages are green, and the check was re-run against the live site.
3. **README now opens with a screenshot** of the live demo. The smoke check is saved as `scripts/check_demo.py`.
4. **AWS deploy skipped.** There's no AWS CLI and no credentials on this machine. Nothing was created, and the resume bullet still says "never deployed".
5. **Interview prep written** to `docs/interview-prep.md`: a pitch, 25 Q&As with file:line references, hard follow-ups, and flashcards. It's kept local and not committed.

### Part A: live demo check
- `scripts/check_demo.py` loads https://reeve25.github.io/vulnprio/ at desktop (1440×900) and phone (390×844) widths. It fails on:
  - console errors or page errors
  - failed requests or any HTTP status ≥ 400
  - an empty chart, table or scan list, or a visible status message
  - horizontal page scroll

  Run it with `uv run --with playwright python scripts/check_demo.py`. Playwright is not a project dependency.
- First run: passed at both widths.
  - solr:8.11.0 showed 1,072 findings, 385 HIGH/CRITICAL, 83 act-now and 8 KEV.
  - The KEV catalog was version 2026.09.23.
- The screenshots showed a real bug. At 390 px the Package and "Installed → fix" columns wrapped one character per line. Root cause: `overflow-wrap: anywhere` drops those cells' min-content width to about 1ch, so table auto-layout shrank them instead of letting `.table-wrap` scroll.
  - A first attempt, `table { min-width: 720px }`, didn't help. Measured column widths showed the extra width going to the Why column.
  - The fix is `td.pkg, td.ver { min-width: 150px }` in the phone media query. Commit `9e393b6`.
- Pushed; CI and Pages both passed on `b8ab54e`. Re-ran the check against the live site after deploy: both widths pass, and the new CSS is served.
- Screenshots are in `docs/screenshots/` (`desktop`, `phone`, and `-chart` / `-table` variants of each). The desktop one now leads the README and replaces the older `docs/dashboard.png`.

### Part B: AWS deploy (skipped)
- There is no `aws` binary on the PATH in Git Bash or PowerShell, no `~/.aws`, and no `AWS_*` environment variables, so `aws sts get-caller-identity` could not run. As instructed, I skipped all of Part B.
- Terraform isn't installed locally either (CI installs it).
- **You need to:**
  1. Create an AWS account and enable MFA on the root user.
  2. Create an IAM Identity Center user.
  3. Install AWS CLI v2 and run `aws configure sso` then `aws sso login`.
  4. Install Terraform ≥ 1.11.

  After that, Part B can run as written.
- **Watch for on first apply:** a new account's Lambda concurrency quota may reject `reserved_concurrent_executions = 10` (`infra/lambda.tf:12`).
- No AWS resources were created, so there's nothing to tear down. The Budget was not created, since there's no account.
- Resume bullet is unchanged. It still correctly says the stack is designed and validated but never deployed. Don't use "deployed and load-tested" until Part B has actually run.

### Part C: interview prep
- `docs/interview-prep.md` contains:
  - a 30-second pitch and a 2-minute walkthrough
  - 25 questions across scoring, serverless and timeouts, data model, security, SRE and scaling, each citing file:line
  - 12 hard follow-ups with honest answers (not deployed; the "84% fewer" framing; httpx timeouts aren't wall-clock; no tenancy; what the mocked `terraform test` does and doesn't prove)
  - 27 flashcards
- It's written as personal coaching ("say this", weak spots), not as design notes, so it isn't committed. It's excluded through `.git/info/exclude` rather than `.gitignore`, so its name doesn't show up in the public repo. Line numbers are pinned to commit `2801145`.

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
- 2026-09-24 — Session 3: applied to us-west-2, e2e + latency measured, destroyed and verified empty. The $5 Budget stays.
