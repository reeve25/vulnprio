import pytest

from vulnprio.parsers import Finding
from vulnprio.scoring import rank, score, summarize


def F(**kw) -> Finding:
    kw.setdefault("vuln_id", kw.get("cve") or "CVE-2020-0001")
    kw.setdefault("cve", kw["vuln_id"] if kw["vuln_id"].startswith("CVE-") else None)
    kw.setdefault("package", "pkg")
    return Finding(**kw)


@pytest.mark.parametrize(
    ("finding", "expected"),
    [
        (F(kev=True, epss=0.0001, cvss=3.1), "P1"),  # KEV beats everything, even a low EPSS/CVSS
        (F(epss=0.10), "P2"),  # threshold is inclusive
        (F(epss=0.0999, cvss=9.8), "P3"),
        (F(epss=0.01), "P3"),
        (F(epss=0.0099, cvss=9.0), "P3"),  # catastrophic impact alone keeps it out of the backlog
        (F(epss=0.0099, cvss=8.9, severity="CRITICAL"), "P4"),  # vendor label alone doesn't promote
        (F(epss=None, cvss=None), "P4"),
        (F(vuln_id="TEMP-0841856-B18BAF", cvss=9.5), "P3"),  # no CVE, still scored on CVSS
    ],
)
def test_tiers(finding, expected):
    score(finding)
    assert finding.priority == expected


def test_reasons_explain_the_decision():
    f = F(kev=True, kev_date_added="2021-12-10", kev_ransomware=True, epss=0.97, epss_percentile=0.999, cvss=10.0)
    f.fixed_version = "2.17.1"
    score(f)
    assert f.reasons == [
        "In CISA KEV (added 2021-12-10)",
        "Known ransomware use",
        "EPSS 97.00% (percentile 99.9)",
        "CVSS 10.0",
        "Fix: 2.17.1",
    ]
    g = F(vuln_id="DLA-1234-1")
    score(g)
    assert g.reasons == ["No CVE id (DLA-1234-1); scored on CVSS only", "No fix available"]


def test_rank_orders_by_tier_then_fixability_then_epss():
    findings = [
        F(vuln_id="CVE-1-4", epss=0.001),
        F(vuln_id="CVE-1-2a", epss=0.2),
        F(vuln_id="CVE-1-2b", epss=0.5),
        F(vuln_id="CVE-1-2c", epss=0.3, fixed_version="1.1"),
        F(vuln_id="CVE-1-1", kev=True),
    ]
    assert [f.vuln_id for f in rank(findings)] == ["CVE-1-1", "CVE-1-2c", "CVE-1-2b", "CVE-1-2a", "CVE-1-4"]


def test_summary_contrasts_severity_with_priority():
    findings = rank(
        [
            F(severity="CRITICAL", cvss=9.8, epss=0.001),
            F(severity="HIGH", cvss=7.5, epss=0.002),
            F(severity="HIGH", kev=True, fixed_version="2"),
            F(severity="LOW", epss=0.4),
        ]
    )
    s = summarize(findings)
    assert s["total"] == 4
    assert s["high_or_critical"] == 3
    assert s["act_now"] == 2
    assert s["fixable_act_now"] == 1
    assert s["by_priority"] == {"P1": 1, "P2": 1, "P3": 1, "P4": 1}
