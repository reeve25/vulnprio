import gzip
import json
from pathlib import Path

import pytest

from vulnprio import parsers
from vulnprio.parsers import ParseError, parse

SAMPLES = Path(__file__).parent.parent / "samples"


def _json(doc) -> bytes:
    return json.dumps(doc).encode()


def test_trivy_sample():
    r = parse((SAMPLES / "trivy_node_16-bullseye-slim.json.gz").read_bytes())
    assert r.format == "trivy"
    assert r.artifact == "node:16-bullseye-slim"
    assert len(r.findings) > 400
    # both OS packages and npm packages are picked up
    assert {"apt", "@tootallnate/once"} <= {f.package for f in r.findings}


def test_grype_sample_maps_ghsa_to_cve():
    r = parse((SAMPLES / "grype_python_3.9-slim-bullseye.json.gz").read_bytes())
    assert r.format == "grype"
    assert r.artifact == "python:3.9-slim-bullseye"
    ghsa = [f for f in r.findings if f.vuln_id.startswith("GHSA-")]
    assert ghsa, "sample should contain GHSA-keyed matches"
    assert all(f.cve and f.cve.startswith("CVE-") for f in ghsa)


def test_sarif_sample():
    r = parse((SAMPLES / "trivy_nginx_1.21.sarif.gz").read_bytes())
    assert r.format == "sarif"
    first = r.findings[0]
    assert (first.cve, first.package, first.installed_version) == ("CVE-2011-3374", "apt", "2.2.4")
    assert first.fixed_version is None  # "Fixed Version: " is empty in the message


def test_same_scan_same_findings_across_formats():
    trivy = parse((SAMPLES / "trivy_nginx_1.21.json.gz").read_bytes())
    sarif = parse((SAMPLES / "trivy_nginx_1.21.sarif.gz").read_bytes())
    assert {(f.cve, f.package) for f in trivy.findings} == {(f.cve, f.package) for f in sarif.findings}


def test_trivy_prefers_nvd_cvss_and_vendor_cve_alias():
    doc = {
        "SchemaVersion": 2,
        "ArtifactName": "x",
        "Results": [
            {
                "Target": "t",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "GHSA-aaaa-bbbb-cccc",
                        "VendorIDs": ["CVE-2024-1234"],
                        "PkgName": "p",
                        "Severity": "high",
                        "SeveritySource": "ghsa",
                        "CVSS": {"ghsa": {"V3Score": 5.0}, "nvd": {"V3Score": 9.8}},
                    }
                ],
            },
            {"Target": "empty", "Vulnerabilities": None},
        ],
    }
    (f,) = parse(_json(doc)).findings
    assert (f.cve, f.cvss, f.severity) == ("CVE-2024-1234", 9.8, "HIGH")


def test_grype_minimal_and_negligible():
    doc = {
        "matches": [
            {
                "vulnerability": {"id": "CVE-2020-0001", "severity": "Negligible", "fix": {"versions": ["1.2", "2.0"]}},
                "artifact": {"name": "lib", "version": "1.0"},
            }
        ],
        "source": {"target": "img:1"},
    }
    r = parse(_json(doc))
    (f,) = r.findings
    assert r.artifact == "img:1"
    assert (f.severity, f.fixed_version, f.cvss) == ("LOW", "1.2, 2.0", None)


def test_csv_with_aliases_and_bad_values():
    data = (
        b"\xef\xbb\xbfCVE_ID,Package,Version,Fixed,Severity,CVSS\n"
        b"CVE-2021-44228,log4j-core,2.14.1,2.17.1,critical,10.0\n"
        b"cve-2022-0001,x,1,,weird,99\n"
        b",skipped,,,,\n"
    )
    fs = parse(data).findings
    assert len(fs) == 2
    assert (fs[0].cve, fs[0].package, fs[0].fixed_version, fs[0].cvss) == (
        "CVE-2021-44228",
        "log4j-core",
        "2.17.1",
        10.0,
    )
    assert (fs[1].cve, fs[1].severity, fs[1].cvss) == ("CVE-2022-0001", "UNKNOWN", None)  # out-of-range CVSS dropped


def test_gzip_and_plain_input_match():
    packed = (SAMPLES / "trivy_python_3.9-slim-bullseye.json.gz").read_bytes()
    assert len(parse(gzip.decompress(packed)).findings) == len(parse(packed).findings) > 0


def test_duplicate_findings_are_collapsed():
    v = {"VulnerabilityID": "CVE-2020-1", "PkgName": "a", "InstalledVersion": "1"}
    doc = {"SchemaVersion": 2, "Results": [{"Target": "t", "Vulnerabilities": [v, v]}]}
    assert len(parse(_json(doc)).findings) == 1


def test_long_strings_truncated():
    doc = {"matches": [{"vulnerability": {"id": "CVE-2020-0001"}, "artifact": {"name": "a" * 10_000}}]}
    assert len(parse(_json(doc)).findings[0].package) == 256


@pytest.mark.parametrize(
    "data",
    [b"", b"   ", b"[1,2]", b'{"foo": 1}', b"\xff\xfe\x00bad", b"name,version\na,1\n", b"\x1f\x8bnot-gzip"],
)
def test_rejects_garbage(data):
    with pytest.raises(ParseError):
        parse(data)


def test_gzip_bomb_rejected(monkeypatch):
    monkeypatch.setattr(parsers, "MAX_DECOMPRESSED", 1000)
    with pytest.raises(ParseError, match="too large"):
        parse(gzip.compress(b"x" * 5000))
