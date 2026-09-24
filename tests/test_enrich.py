import httpx

from vulnprio.enrich import EPSS_BATCH, Enricher
from vulnprio.parsers import Finding

KEV_DOC = {
    "catalogVersion": "2026.09.23",
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2023-4863", "dateAdded": "2023-09-13", "knownRansomwareCampaignUse": "Unknown"},
    ],
}
NVD_DOC = {
    "vulnerabilities": [
        {
            "cve": {
                "metrics": {
                    "cvssMetricV31": [
                        {"type": "Secondary", "cvssData": {"baseScore": 7.0}},
                        {"type": "Primary", "cvssData": {"baseScore": 8.8}},
                    ]
                }
            }
        }
    ]
}


class FakeFeeds:
    """httpx.MockTransport handler that records calls and can fail per-source."""

    def __init__(self, fail=()):
        self.fail = set(fail)
        self.calls = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        self.calls.append(host)
        if host in self.fail:
            return httpx.Response(503)
        if host == "www.cisa.gov":
            return httpx.Response(200, json=KEV_DOC)
        if host == "api.first.org":
            cves = request.url.params["cve"].split(",")
            data = [
                {"cve": c, "epss": "0.5", "percentile": "0.99", "date": "2026-09-23"}
                for c in cves
                if c != "CVE-2099-0001"
            ]
            return httpx.Response(200, json={"data": data})
        if host == "services.nvd.nist.gov":
            return httpx.Response(200, json=NVD_DOC)
        return httpx.Response(404)


def make(fail=()):
    feeds = FakeFeeds(fail)
    return Enricher(httpx.Client(transport=httpx.MockTransport(feeds))), feeds


def test_kev_epss_and_nvd_fallback():
    enricher, _ = make()
    log4j = Finding("CVE-2021-44228", "CVE-2021-44228", "log4j", cvss=10.0)
    no_cvss = Finding("CVE-2023-4863", "CVE-2023-4863", "libwebp")
    unscored = Finding("CVE-2099-0001", "CVE-2099-0001", "x", cvss=5.0)
    no_cve = Finding("DLA-1-1", None, "y")
    assert enricher.enrich([log4j, no_cvss, unscored, no_cve]) == []

    assert (log4j.kev, log4j.kev_date_added, log4j.kev_ransomware) == (True, "2021-12-10", True)
    assert (log4j.epss, log4j.epss_percentile, log4j.epss_date) == (0.5, 0.99, "2026-09-23")
    assert (no_cvss.kev, no_cvss.kev_ransomware, no_cvss.cvss) == (True, False, 8.8)  # NVD Primary wins
    assert (unscored.epss, unscored.kev) == (None, False)
    assert enricher.kev_version == "2026.09.23"


def test_cache_avoids_refetching():
    enricher, feeds = make()
    findings = [Finding("CVE-2021-44228", "CVE-2021-44228", "a", cvss=1.0)]
    enricher.enrich(findings)
    enricher.enrich(findings)
    assert feeds.calls == ["www.cisa.gov", "api.first.org"]


def test_epss_batching():
    enricher, feeds = make()
    findings = [Finding(f"CVE-2020-{i:05d}", f"CVE-2020-{i:05d}", "p", cvss=1.0) for i in range(EPSS_BATCH * 2 + 1)]
    enricher.enrich(findings)
    assert feeds.calls.count("api.first.org") == 3
    assert all(f.epss == 0.5 for f in findings)


def test_source_failures_degrade_gracefully():
    enricher, _ = make(fail={"www.cisa.gov", "api.first.org", "services.nvd.nist.gov"})
    f = Finding("CVE-2021-44228", "CVE-2021-44228", "log4j")
    errors = enricher.enrich([f])
    assert errors == [
        "CISA KEV unavailable",
        "EPSS unavailable (some scores missing)",
        "NVD unavailable (some CVSS scores missing)",
    ]
    assert (f.kev, f.epss, f.cvss) == (False, None, None)


def test_nvd_lookups_are_capped():
    enricher, feeds = make()
    findings = [Finding(f"CVE-2020-{i:05d}", f"CVE-2020-{i:05d}", "p") for i in range(20)]
    enricher.enrich(findings)
    assert feeds.calls.count("services.nvd.nist.gov") == 5


def test_failed_kev_refresh_keeps_last_catalog():
    enricher, feeds = make()
    enricher.enrich([Finding("CVE-2021-44228", "CVE-2021-44228", "a", cvss=1.0)])
    enricher._kev_at = float("-inf")  # force a refresh, which now fails
    feeds.fail.add("www.cisa.gov")
    f = Finding("CVE-2021-44228", "CVE-2021-44228", "a", cvss=1.0)
    assert enricher.enrich([f]) == ["CISA KEV unavailable"]
    assert f.kev
