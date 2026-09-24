# Progress

## Log
- 2026-09-23 — Plan: SPEC.md + DECISIONS.md, critiqued by a review subagent (senior infra + recruiter lenses); revised: 4 MB sync cap, priority in sort key, SigV4 clients, waivers, LocalStack pinned 4.14 (latest needs a token — verified), checkov only, terraform test.
- 2026-09-23 — Samples: real Trivy (JSON + SARIF) and Grype scans of public images python:3.9-slim-bullseye, node:16-bullseye-slim, nginx:1.21, stored gzipped.
- 2026-09-23 — Slice 1 parsers: Trivy/Grype/SARIF/CSV + gzip, GHSA→CVE aliasing, dedup. 18 tests.
- 2026-09-23 — Slice 7 dashboard: one static page, two modes (Pages demo from precomputed JSON; live under /ui/ with upload). textContent-only rendering under a strict CSP. Screenshot in docs/dashboard.png.
- 2026-09-23 — Review of parse/enrich/score (subagent) fixed: wrong-shaped JSON, corrupt gzip, oversize CSV fields and deep nesting all returned 500 → now 400 via one guard in `parse()`; finding/CVE caps against memory and outbound-call amplification; CVE regex bounded; SARIF `security-severity` no longer stored as CVSS (Trivy's value is a per-severity constant: LOW=2.0 where NVD says 7.5); Trivy output with no `Results` accepted; a failed KEV refresh no longer drops the cached catalog; removed unused `ttl` param. 58 unit tests.
