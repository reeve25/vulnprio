# Research notes (sources for the scoring model)

Gathered 2026-09-23. Numbers marked *v3* come from the EPSS v3 paper; FIRST currently runs EPSS **v5** (v2026.06.15).

## EPSS
- Jacobs, Romanosky, Suciu, Edwards, Sarabi. *Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights.* IEEE EuroS&PW 2023. https://arxiv.org/abs/2302.14172
  - 6.4% (12,243 of 192,035) of published CVEs were observed exploited (data Jul 2016 – Dec 2022). *v3*
  - Remediating CVSS ≥ 7: 82.1% coverage, requires fixing 58.1% of all CVEs, 3.9% efficiency. *v3*
  - EPSS ≥ 0.088: 82.0% coverage, 7.3% of CVEs, 45.5% efficiency — "one-eighth" the effort. *v3*
  - At equal effort (~15% of CVEs): CVSS ≥ 9.1 → 33.5% coverage; EPSS ≥ 0.022 → 90.4% coverage. *v3*
  - KEV alone: 0.5% effort, 53.2% efficiency, only 5.9% coverage (KEV as of 2022-12-01). *v3*
- FIRST "Using EPSS": https://www.first.org/epss/using-epss
  - ~2–3% of published CVEs see exploitation activity in any 30-day window.
  - Treat KEV-listed CVEs as exploited and prioritize them regardless of EPSS.
  - "Do not multiply an EPSS score by an ordinal (such as CVSS)" to make a combined risk score.
- Model versions: https://www.first.org/epss/data — v3 2023-03-07, v4 2025-03-17, v5 2026-06-15.
- API: https://api.first.org/data/v1/epss — `?cve=A,B`; `cve` param max 2000 chars; rate limits undocumented; bulk users should use the daily CSV.

## CISA KEV
- Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json (catalog 2026.09.23: 1,721 entries).
- BOD 22-01 (2021) — revoked 2026-06-10: https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities-revoked
- BOD 26-04 (2026-06-10) — SSVC-informed deadlines (3 / 14 / 60 days) using exposure, KEV listing, automatability, technical impact: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk

## NVD
- API 2.0: 5 requests / rolling 30 s without key, 50 with key. https://nvd.nist.gov/developers/start-here (page is JS-rendered; figures corroborated by third parties).

## CVSS inflation
- 2025: 39.4% of 48,185 new CVEs rated High or Critical. https://jerrygamblin.com/2026/01/01/2025-cve-data-review/
