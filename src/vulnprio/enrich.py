"""Enrich findings with CISA KEV membership, FIRST EPSS scores, and (as a fallback) NVD CVSS.

Enrichment never fails an ingest: each source is independent, failures are
collected and returned so the scan summary can say what's missing.
"""

import logging
import time

import httpx

from .parsers import Finding

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BATCH = 100  # FIRST caps the `cve` param at 2000 chars; 100 IDs stays well under
NVD_MAX_LOOKUPS = 5  # public NVD API allows 5 requests / 30 s without a key
NVD_BUDGET_S = 8.0  # keep ingest well inside API Gateway's 30 s integration timeout
CACHE_TTL_S = 24 * 3600

log = logging.getLogger(__name__)


class Enricher:
    """Holds a per-process cache so a warm Lambda makes ~zero external calls."""

    def __init__(self, client: httpx.Client | None = None):
        self.client = client or httpx.Client(timeout=10.0, headers={"User-Agent": "vulnprio"})
        self._kev: dict[str, dict] = {}
        self._kev_at = float("-inf")
        self.kev_version: str | None = None
        # ponytail: unbounded dicts; fine for thousands of CVEs, use an LRU if a process sees millions
        self._epss: dict[str, tuple[float, float, str] | None] = {}
        self._nvd: dict[str, float | None] = {}
        self._scores_at = time.monotonic()

    def _load_kev(self) -> None:
        if time.monotonic() - self._kev_at < CACHE_TTL_S:
            return
        resp = self.client.get(KEV_URL)
        resp.raise_for_status()
        doc = resp.json()
        self._kev = {
            v["cveID"]: {"date_added": v.get("dateAdded"), "ransomware": v.get("knownRansomwareCampaignUse") == "Known"}
            for v in doc["vulnerabilities"]
        }
        self.kev_version = doc.get("catalogVersion")
        self._kev_at = time.monotonic()

    def _load_epss(self, cves: list[str]) -> None:
        if time.monotonic() - self._scores_at > CACHE_TTL_S:
            self._epss.clear()
            self._nvd.clear()
            self._scores_at = time.monotonic()
        todo = [c for c in cves if c not in self._epss]
        for i in range(0, len(todo), EPSS_BATCH):
            batch = todo[i : i + EPSS_BATCH]
            resp = self.client.get(EPSS_URL, params={"cve": ",".join(batch), "limit": len(batch)})
            resp.raise_for_status()
            got = {
                row["cve"]: (float(row["epss"]), float(row["percentile"]), row.get("date"))
                for row in resp.json().get("data", [])
            }
            for cve in batch:
                self._epss[cve] = got.get(cve)  # None = FIRST has no score (e.g. brand-new or rejected CVE)

    def _nvd_cvss(self, cve: str) -> float | None:
        if cve not in self._nvd:
            resp = self.client.get(NVD_URL, params={"cveId": cve})
            resp.raise_for_status()
            score = None
            for vuln in resp.json().get("vulnerabilities", []):
                metrics = vuln.get("cve", {}).get("metrics", {})
                for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
                    for m in metrics.get(key, []):
                        if m.get("type") == "Primary" or score is None:
                            score = m.get("cvssData", {}).get("baseScore", score)
                    if score is not None:
                        break
            self._nvd[cve] = score
        return self._nvd[cve]

    def enrich(self, findings: list[Finding]) -> list[str]:
        """Mutate findings in place; return a list of human-readable enrichment errors."""
        errors = []
        cves = sorted({f.cve for f in findings if f.cve})

        try:
            self._load_kev()
        except (httpx.HTTPError, ValueError, KeyError) as e:
            log.warning("kev enrichment failed: %s", e)
            errors.append("CISA KEV unavailable")
        # Applied outside the try: a failed refresh still uses the last good catalog.
        for f in findings:
            if f.cve and (hit := self._kev.get(f.cve)):
                f.kev, f.kev_date_added, f.kev_ransomware = True, hit["date_added"], hit["ransomware"]

        try:
            self._load_epss(cves)
        except (httpx.HTTPError, ValueError, KeyError) as e:
            log.warning("epss enrichment failed: %s", e)
            errors.append("EPSS unavailable (some scores missing)")
        for f in findings:
            if f.cve and (hit := self._epss.get(f.cve)):
                f.epss, f.epss_percentile, f.epss_date = hit

        missing = sorted({f.cve for f in findings if f.cve and f.cvss is None})
        deadline = time.monotonic() + NVD_BUDGET_S
        scores = {}
        for cve in missing[:NVD_MAX_LOOKUPS]:
            if time.monotonic() > deadline:
                break
            try:
                scores[cve] = self._nvd_cvss(cve)
            except (httpx.HTTPError, ValueError) as e:
                log.warning("nvd lookup failed for %s: %s", cve, e)
                errors.append("NVD unavailable (some CVSS scores missing)")
                break  # 403/429 means we're rate limited; don't keep hammering
        for f in findings:
            if f.cvss is None and scores.get(f.cve) is not None:
                f.cvss = scores[f.cve]
        return errors
