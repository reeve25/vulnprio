from datetime import date

import pytest

from vulnprio import cli


class FakeEnricher:
    kev_version = None

    def enrich(self, findings):
        for f in findings:
            f.kev = f.cve in ("CVE-2021-44228", "CVE-2023-0001")
        return []


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(cli, "Enricher", FakeEnricher)


@pytest.fixture
def scan(tmp_path):
    p = tmp_path / "scan.csv"
    p.write_text("cve,package,fixed_version\nCVE-2021-44228,log4j-core,2.17.1\nCVE-2023-0001,nofix,\nCVE-2020-9,x,1\n")
    return p


def test_gate_fails_on_fixable_p1(scan, tmp_path, capsys):
    assert cli.main(["gate", str(scan), "--waivers", str(tmp_path / "none")]) == 1
    out = capsys.readouterr().out
    assert "FAIL: 1 finding(s)" in out and "log4j-core" in out and "nofix" not in out.split("FAIL")[1]


def test_gate_include_unfixed(scan, tmp_path):
    assert cli.main(["gate", str(scan), "--include-unfixed", "--waivers", str(tmp_path / "none")]) == 1


def test_gate_passes_with_active_waiver(scan, tmp_path, capsys):
    w = tmp_path / "w"
    w.write_text("# comment\nCVE-2021-44228 2999-01-01 vendor patch scheduled for sprint 12\n")
    assert cli.main(["gate", str(scan), "--waivers", str(w)]) == 0
    assert "PASS" in capsys.readouterr().out


def test_expired_or_malformed_waivers_fail_the_gate(scan, tmp_path):
    w = tmp_path / "w"
    w.write_text("CVE-2021-44228 2000-01-01 old excuse\n")
    assert cli.main(["gate", str(scan), "--waivers", str(w)]) == 1
    _, problems = cli.load_waivers(w, date(2026, 1, 1))
    assert "expired" in problems[0]
    w.write_text("CVE-2021-44228 2999-01-01\nCVE-X notadate why\n")
    active, problems = cli.load_waivers(w, date(2026, 1, 1))
    assert active == set() and len(problems) == 2  # reason is mandatory


def test_analyze_prints_headline(scan, capsys):
    assert cli.main(["analyze", str(scan)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("3 findings, 0 HIGH/CRITICAL by severity -> 2 need action now")


def test_bad_file_exits_2(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert cli.main(["analyze", str(bad)]) == 2
    assert cli.main(["analyze", str(tmp_path / "missing")]) == 2


def test_gate_fails_closed_when_exploit_data_missing(scan, tmp_path, monkeypatch, capsys):
    class DownEnricher(FakeEnricher):
        def enrich(self, findings):
            return ["CISA KEV unavailable", "NVD unavailable (some CVSS scores missing)"]

    monkeypatch.setattr(cli, "Enricher", DownEnricher)
    assert cli.main(["gate", str(scan), "--waivers", str(tmp_path / "none")]) == 1
    out = capsys.readouterr().out
    assert "enrichment failed: CISA KEV unavailable" in out and "NVD" not in out


def test_gate_rejects_unknown_tiers(scan, capsys):
    assert cli.main(["gate", str(scan), "--fail-on", "P1;P2"]) == 2
    assert "--fail-on" in capsys.readouterr().err
