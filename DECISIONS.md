# Decisions

Short ADR-style log. Newest last.

### 1. Python + FastAPI over Go
The work is JSON/CSV parsing, HTTP enrichment, and a small API — Python's stdlib (`json`, `csv`) plus pydantic validation cover it with the least code, and it's the language I can defend line by line. FastAPI gives typed request validation and OpenAPI docs for free. Go would win on cold start and binary size; Lambda Web Adapter + a slim image keeps Python cold starts acceptable for a low-traffic internal tool. Revisit if p99 cold start breaks the SLO.

### 2. Transparent priority tiers instead of a single 0–100 score
A made-up weighted formula is hard to defend and hard for an engineer to act on. Tiers map to public, citable signals: KEV = *known* exploited (an input to CISA BOD 26-04 deadlines; FIRST says prioritize KEV regardless of EPSS), EPSS = *probability* of exploitation in 30 days, CVSS = *impact*. FIRST explicitly warns against multiplying EPSS by CVSS into one score, which is what most "risk score" tools do. Sources in `docs/RESEARCH.md`. Every finding carries `reasons[]` so the ranking is auditable. Thresholds (0.10, 0.01, 9.0) are constants in `scoring.py`, justified in the README; not configurable until someone needs it.

### 3. Lambda (container image) + API Gateway HTTP API, not ECS Fargate
Traffic is bursty and low (a few scans per CI run), so pay-per-request Lambda costs ~$0 at idle while Fargate bills 24/7 plus an ALB (~$16/mo minimum). HTTP API is ~70% cheaper than REST API and supports IAM auth. The Lambda runs the *same* container as local dev via AWS Lambda Web Adapter, so there is no Mangum shim and no Lambda-only code path.

### 4. DynamoDB single table over RDS Postgres
Access patterns are fixed and key-based (get scan, list scans, page findings in rank order). On-demand DynamoDB has no idle cost, no VPC/NAT requirement (RDS would force the Lambda into a VPC and add a NAT gateway ~$32/mo), and LocalStack emulates it well. Trade-off: no ad-hoc SQL across scans — acceptable for v1.

### 5. Findings stored pre-sorted (`SK=F#{priority}#{rank}`)
Ranking happens once at ingest; reads are a single Query in rank order. Putting the tier in the sort key makes `?priority=P1` a `begins_with` key condition, so `Limit` + cursor pagination stays correct (filtering after `Limit` would return short/empty pages). No GSI needed.

### 6. In-process enrichment cache, no cache table
KEV is one 1.7 MB file; EPSS is batched 100/request. A per-container 24 h cache means a warm Lambda does ~zero external calls. A DynamoDB cache table would add IAM, cost, and code for no measured benefit. Upgrade path: a scheduled job that snapshots KEV + the full EPSS CSV to S3 daily.

### 7. CloudWatch Embedded Metric Format for metrics
Metrics are emitted as structured log lines that CloudWatch extracts asynchronously — zero `PutMetricData` calls, zero added latency, no extra IAM permission, and they're still readable as plain logs locally.

### 8. checkov instead of tfsec
tfsec is in maintenance mode (its checks moved into Trivy). One IaC scanner is enough; two means double the suppressions. Skipped checks are suppressed inline with a written reason, never globally.

### 9. Terraform is validated, never applied
Requirement: no real AWS spend. CI runs `fmt -check`, `init -backend=false`, `validate`, and IaC scanners. Local dev runs the same container against LocalStack S3 + DynamoDB rather than applying the Terraform to LocalStack (API Gateway v2 and ECR are paid LocalStack features). Least privilege is proven with `terraform test` + `mock_provider` instead of a real apply.
*Update 2026-09-24:* applied once to us-west-2 behind a $5 AWS Budget, measured, then destroyed (#17, #18, `docs/SLO.md`). The default posture is still "not running"; state stayed local because the stack lived for about 2 hours.

### 10. Dogfooding in CI
The container-scan job pipes Trivy's JSON for vulnprio's own image into `vulnprio gate`, failing the build on P1/P2 findings that have a fix. This is the product's thesis applied to itself: block on exploitable risk, not on raw severity counts.

### 11. Static demo on GitHub Pages
Recruiters get a zero-setup link. The page is the same `index.html` the API serves at `/ui/`; in static mode it reads precomputed JSON built by CI from real scans of public images. No backend to keep alive, no cost.

### 12. Tooling
`uv` for env/lock, `ruff` for lint+format, `pytest` + `pytest-cov`, `httpx` (already a FastAPI test dependency) as the HTTP client so enrichment tests use `httpx.MockTransport` instead of a mocking library.

### 13. LocalStack pinned to 4.14
`localstack/localstack:latest` (2026.x) exits without `LOCALSTACK_AUTH_TOKEN`. A token would be a CI secret unavailable to fork PRs. 4.14 is the newest tag verified to start tokenless and covers S3 + DynamoDB. Fallback if it disappears: moto server mode.

### 14. Synchronous ingest, sized to fit AWS hard limits
API Gateway HTTP API integrations time out at 30 s (not raisable) and Lambda sync payloads cap at 6 MB (bodies arrive base64-encoded). So: 4 MB body cap, gzip accepted, NVD capped at 5 lookups per scan. Upgrade path when scans get bigger: presigned S3 PUT → S3 event → async worker.

### 15. API clients authenticate with SigV4 (IAM auth), not API keys
No shared secrets to rotate; CI gets short-lived credentials via GitHub OIDC. The dashboard is therefore not served through API Gateway (browsers can't sign SigV4); the public UI is the static Pages demo.

### 16. Findings stored as a JSON string attribute
Avoids boto3's float→Decimal conversion on every numeric field. Findings are never queried by attribute, only by key, so nothing is lost.

### 17. Reserved concurrency is a variable; new accounts set it to -1
First real apply (2026-09-24) failed on `PutFunctionConcurrency`: *"Specified ReservedConcurrentExecutions for function decreases account's UnreservedConcurrentExecution below its minimum value of [10]."* A new account's Lambda concurrency quota is 10 (not the documented 1,000 default), and AWS always keeps 10 unreserved, so **any** reservation fails. Terraform had already created the function and marked it tainted; a re-apply with `reserved_concurrency = -1` replaced it cleanly. The cost/abuse ceiling then comes from the API Gateway stage throttle (10 rps, burst 20) plus the account quota of 10. Once the quota is raised (Service Quotas request), set it back to 10.

Nothing else broke on AWS: the KMS key policy's encryption-context grant let CloudWatch Logs create both encrypted log groups, and a forced `ALARM` state published to the KMS-encrypted SNS topic (`Successfully executed action`). Two local-tooling snags, not AWS issues: Windows PowerShell 5.1 corrupts `aws ecr get-login-password | docker login` (it rewrites piped native output, and ECR answers 400), so do that from Git Bash; and Git Bash rewrites `/aws/lambda/...` log group names into Windows paths (`MSYS_NO_PATHCONV=1`). The image is built with `--provenance=false`, because Lambda rejects the multi-manifest index BuildKit produces by default.

### 18. `allow_destroy` for the demo teardown
DynamoDB deletion protection, a non-empty versioned bucket and a non-empty ECR repo each block `terraform destroy`, which is the point for real data. `var.allow_destroy` (default `false`) flips all three: apply with `true`, then destroy. That keeps the safe default in code and makes teardown a two-command, reviewed step instead of manual console deletes. The KMS key can't be deleted immediately; `deletion_window_in_days = 7` (the minimum) and AWS doesn't bill keys pending deletion.
