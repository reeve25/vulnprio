"""Rank findings into transparent priority tiers.

P1  in CISA KEV                    -> known exploited in the wild
P2  EPSS >= 0.10                   -> high probability of exploitation in the next 30 days
P3  EPSS >= 0.01 or CVSS >= 9.0    -> plausible exploitation, or catastrophic impact
P4  everything else

Deliberately NOT a blended number: FIRST advises against multiplying EPSS by
CVSS. Thresholds are round numbers near the EPSS v3 paper's efficient
operating points (0.088 for ~82% coverage); see docs/RESEARCH.md.
"""

from collections import Counter

from .parsers import Finding

EPSS_URGENT = 0.10
EPSS_PLAUSIBLE = 0.01
CVSS_CRITICAL = 9.0
PRIORITIES = ("P1", "P2", "P3", "P4")


def score(f: Finding) -> None:
    """Set f.priority and f.reasons."""
    reasons = []
    if f.kev:
        reasons.append(f"In CISA KEV (added {f.kev_date_added})" if f.kev_date_added else "In CISA KEV")
        if f.kev_ransomware:
            reasons.append("Known ransomware use")
    if f.epss is not None:
        pct = f" (percentile {f.epss_percentile * 100:.1f})" if f.epss_percentile is not None else ""
        reasons.append(f"EPSS {f.epss:.2%}{pct}")
    elif f.cve:
        reasons.append("No EPSS score")
    else:
        reasons.append(f"No CVE id ({f.vuln_id}); scored on severity only")
    if f.cvss is not None:
        reasons.append(f"CVSS {f.cvss:.1f}")
    reasons.append(f"Fix: {f.fixed_version}" if f.fixed_version else "No fix available")

    epss = f.epss or 0.0
    if f.kev:
        f.priority = "P1"
    elif epss >= EPSS_URGENT:
        f.priority = "P2"
    elif epss >= EPSS_PLAUSIBLE or (f.cvss or 0.0) >= CVSS_CRITICAL:
        f.priority = "P3"
    else:
        f.priority = "P4"
    f.reasons = reasons


def rank(findings: list[Finding]) -> list[Finding]:
    """Score every finding and return them most-urgent first.

    Within a tier: fixable first (actionable today), then EPSS, then CVSS.
    """
    for f in findings:
        score(f)
    return sorted(
        findings,
        key=lambda f: (f.priority, not f.fixed_version, -(f.epss or 0.0), -(f.cvss or 0.0), f.vuln_id, f.package),
    )


def summarize(findings: list[Finding]) -> dict:
    """Headline numbers: how much CVSS-only triage would flag vs what actually needs action."""
    by_priority = Counter(f.priority for f in findings)
    by_severity = Counter(f.severity for f in findings)
    return {
        "total": len(findings),
        "by_priority": {p: by_priority.get(p, 0) for p in PRIORITIES},
        "by_severity": dict(by_severity.most_common()),
        "high_or_critical": by_severity.get("CRITICAL", 0) + by_severity.get("HIGH", 0),
        "act_now": by_priority.get("P1", 0) + by_priority.get("P2", 0),
        "kev": sum(f.kev for f in findings),
        "fixable_act_now": sum(1 for f in findings if f.priority in ("P1", "P2") and f.fixed_version),
    }
