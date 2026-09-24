"""Normalize scanner output (Trivy JSON, Grype JSON, SARIF 2.1.0, CSV) into Findings.

Everything here handles untrusted input: formats are detected structurally,
strings are truncated, numbers are range-checked, and anything unrecognised
raises ParseError (the API turns that into a 400).
"""

import csv
import gzip
import io
import json
import re
from dataclasses import dataclass, field

MAX_DECOMPRESSED = 50 * 1024 * 1024  # zip-bomb guard for gzip uploads
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


class ParseError(ValueError):
    pass


@dataclass
class Finding:
    vuln_id: str
    cve: str | None
    package: str
    installed_version: str | None = None
    fixed_version: str | None = None
    severity: str = "UNKNOWN"
    cvss: float | None = None
    target: str | None = None
    # enrichment
    kev: bool = False
    kev_date_added: str | None = None
    kev_ransomware: bool = False
    epss: float | None = None
    epss_percentile: float | None = None
    epss_date: str | None = None
    # scoring
    priority: str | None = None
    reasons: list[str] = field(default_factory=list)


@dataclass
class Report:
    format: str
    artifact: str | None
    findings: list[Finding]


def _s(value, limit: int = 256) -> str | None:
    """Coerce an untrusted value to a bounded string (or None if empty)."""
    if value is None or value == "":
        return None
    return str(value)[:limit]


def _score(value) -> float | None:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if 0.0 <= f <= 10.0 else None


def _severity(value) -> str:
    s = str(value or "").strip().upper()
    if s == "NEGLIGIBLE":
        return "LOW"
    return s if s in SEVERITIES else "UNKNOWN"


def _severity_from_score(score: float | None) -> str:
    # GitHub code-scanning convention for SARIF `security-severity`
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0 else "UNKNOWN"


def _cve(*candidates) -> str | None:
    for c in candidates:
        if isinstance(c, str) and (m := CVE_RE.fullmatch(c.strip().upper())):
            return m.group(0)
    return None


def _trivy(doc: dict) -> Report:
    findings = []
    for result in doc.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            cvss = None
            sources = v.get("CVSS") or {}
            for src in ["nvd", v.get("SeveritySource"), *sources]:
                entry = sources.get(src) or {}
                if cvss := _score(entry.get("V3Score")) or _score(entry.get("V40Score")):
                    break
            vuln_id = _s(v.get("VulnerabilityID")) or "UNKNOWN"
            findings.append(
                Finding(
                    vuln_id=vuln_id,
                    cve=_cve(vuln_id, *(v.get("VendorIDs") or [])),
                    package=_s(v.get("PkgName")) or "unknown",
                    installed_version=_s(v.get("InstalledVersion")),
                    fixed_version=_s(v.get("FixedVersion")),
                    severity=_severity(v.get("Severity")),
                    cvss=cvss,
                    target=_s(result.get("Target")),
                )
            )
    return Report("trivy", _s(doc.get("ArtifactName")), findings)


def _grype_cvss(entries) -> float | None:
    # Prefer a CVSS v3 score, then anything else that parses.
    entries = [e for e in entries or [] if isinstance(e, dict)]
    for e in sorted(entries, key=lambda e: not str(e.get("version", "")).startswith("3")):
        if (score := _score((e.get("metrics") or {}).get("baseScore"))) is not None:
            return score
    return None


def _grype(doc: dict) -> Report:
    findings = []
    for m in doc.get("matches") or []:
        v = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        related = [r for r in m.get("relatedVulnerabilities") or [] if isinstance(r, dict)]
        fix = v.get("fix") or {}
        locations = art.get("locations") or [{}]
        vuln_id = _s(v.get("id")) or "UNKNOWN"
        findings.append(
            Finding(
                vuln_id=vuln_id,
                # Grype often keys language-package matches by GHSA id; the CVE is an alias.
                cve=_cve(vuln_id, *(r.get("id") for r in related)),
                package=_s(art.get("name")) or "unknown",
                installed_version=_s(art.get("version")),
                fixed_version=_s(", ".join(map(str, fix.get("versions") or []))),
                severity=_severity(v.get("severity")),
                cvss=_grype_cvss([c for r in related for c in r.get("cvss") or []]) or _grype_cvss(v.get("cvss")),
                target=_s(locations[0].get("path")),
            )
        )
    source = (doc.get("source") or {}).get("target")
    artifact = source.get("userInput") if isinstance(source, dict) else source
    return Report("grype", _s(artifact), findings)


_SARIF_FIELDS = {
    "package": re.compile(r"^Package: (.+)$", re.M),
    "installed": re.compile(r"^Installed Version: (.+)$", re.M),
    "fixed": re.compile(r"^Fixed Version: (.+)$", re.M),
    "severity": re.compile(r"^Severity: (\w+)$", re.M),
    # Grype's SARIF phrasing: "... in deb package: libssl1.1, version 1.1.1n ..."
    "pkg_inline": re.compile(r"package: ([^\s,]+), version ([^\s,]+)"),
}


def _sarif(doc: dict) -> Report:
    findings = []
    for run in doc.get("runs") or []:
        rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        by_id = {r.get("id"): r for r in rules if isinstance(r, dict)}
        for res in run.get("results") or []:
            rule_id = res.get("ruleId")
            idx = res.get("ruleIndex")
            rule = rules[idx] if isinstance(idx, int) and 0 <= idx < len(rules) else by_id.get(rule_id, {})
            text = str((res.get("message") or {}).get("text") or "")
            got = {k: rx.search(text) for k, rx in _SARIF_FIELDS.items()}
            inline = got["pkg_inline"]
            # SARIF has no CVSS field; `security-severity` is the closest thing (Trivy fills it
            # with a per-severity constant, e.g. LOW=2.0), so treat it as approximate.
            score = _score((rule.get("properties") or {}).get("security-severity"))
            loc = ((res.get("locations") or [{}])[0].get("physicalLocation") or {}).get("artifactLocation") or {}
            vuln_id = _s(rule_id or rule.get("id")) or "UNKNOWN"
            findings.append(
                Finding(
                    vuln_id=vuln_id,
                    cve=_cve(vuln_id, rule.get("id")) or _cve(*CVE_RE.findall(text)[:1]),
                    package=_s(got["package"] and got["package"].group(1))
                    or _s(inline and inline.group(1))
                    or "unknown",
                    installed_version=_s(got["installed"] and got["installed"].group(1))
                    or _s(inline and inline.group(2)),
                    fixed_version=_s(got["fixed"] and got["fixed"].group(1).strip()),
                    severity=_severity(got["severity"].group(1)) if got["severity"] else _severity_from_score(score),
                    cvss=score,
                    target=_s(loc.get("uri")),
                )
            )
    return Report("sarif", None, findings)


_CSV_ALIASES = {
    "cve": ("cve", "cve_id", "vulnerability", "vulnerability_id", "id"),
    "package": ("package", "pkg", "package_name", "component"),
    "installed_version": ("version", "installed_version", "installed"),
    "fixed_version": ("fixed_version", "fixed", "fix_version"),
    "severity": ("severity",),
    "cvss": ("cvss", "cvss_score", "score"),
    "target": ("target", "asset", "image", "host"),
}


def _csv(text: str) -> Report:
    reader = csv.DictReader(io.StringIO(text))
    headers = {h.strip().lower(): h for h in reader.fieldnames or [] if h}
    cols = {k: next((headers[a] for a in aliases if a in headers), None) for k, aliases in _CSV_ALIASES.items()}
    if not cols["cve"]:
        raise ParseError("CSV needs a 'cve' column")
    findings = []
    for raw in reader:
        row = {k: raw.get(col) if col else None for k, col in cols.items()}
        vuln_id = _s(row["cve"])
        if not vuln_id:
            continue
        findings.append(
            Finding(
                vuln_id=vuln_id,
                cve=_cve(vuln_id),
                package=_s(row["package"]) or "unknown",
                installed_version=_s(row["installed_version"]),
                fixed_version=_s(row["fixed_version"]),
                severity=_severity(row["severity"]),
                cvss=_score(row["cvss"]),
                target=_s(row["target"]),
            )
        )
    return Report("csv", None, findings)


def _decompress(data: bytes) -> bytes:
    if data[:2] != b"\x1f\x8b":
        return data
    try:
        out = gzip.GzipFile(fileobj=io.BytesIO(data)).read(MAX_DECOMPRESSED + 1)
    except (OSError, EOFError) as e:
        raise ParseError(f"bad gzip data: {e}") from None
    if len(out) > MAX_DECOMPRESSED:
        raise ParseError("decompressed upload too large")
    return out


def parse(data: bytes) -> Report:
    """Detect the format of raw scanner output and return normalized findings."""
    try:
        text = _decompress(data).decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ParseError("input is not UTF-8") from None
    if not text.strip():
        raise ParseError("empty input")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        doc = None
    if isinstance(doc, dict):
        if "SchemaVersion" in doc and "Results" in doc:
            report = _trivy(doc)
        elif "matches" in doc:
            report = _grype(doc)
        elif "runs" in doc:
            report = _sarif(doc)
        else:
            raise ParseError("unrecognised JSON: expected Trivy, Grype, or SARIF")
    elif doc is not None:
        raise ParseError("unrecognised JSON: expected an object")
    else:
        report = _csv(text)
    # Scanners repeat a vuln per layer/result; keep one per (vuln, package, version, target).
    seen, unique = set(), []
    for f in report.findings:
        key = (f.vuln_id, f.package, f.installed_version, f.target)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    report.findings = unique
    return report
