"""vulnprio CLI.

vulnprio analyze scan.json               ranked table on stdout
vulnprio gate scan.json --fail-on P1,P2  CI gate: exit 1 on fixable findings in those tiers
vulnprio push scan.json --api URL        upload to a deployed API (SigV4-signed)
"""

import argparse
import sys
from datetime import date
from pathlib import Path

from .enrich import Enricher
from .parsers import ParseError
from .scoring import analyze


def load_waivers(path: Path, today: date) -> tuple[set[str], list[str]]:
    """Parse a waiver file: `CVE-ID  YYYY-MM-DD  reason...` per line, # comments.

    Returns (active waived ids, problems). Expired or malformed waivers are
    problems, so a waiver can't silently become permanent.
    """
    active, problems = set(), []
    if not path.exists():
        return active, problems
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 2)
        try:
            expires = date.fromisoformat(parts[1])
            if len(parts) < 3:
                raise ValueError
        except (IndexError, ValueError):
            problems.append(f"{path}:{n}: expected 'ID YYYY-MM-DD reason'")
            continue
        if expires < today:
            problems.append(f"{path}:{n}: waiver for {parts[0]} expired {expires}")
        else:
            active.add(parts[0])
    return active, problems


def _table(findings, limit: int) -> str:
    rows = [f"{'PRI':<4} {'VULN':<20} {'PACKAGE':<28} {'EPSS':>7} {'CVSS':>5}  {'KEV':<3}  FIX"]
    for f in findings[:limit]:
        epss = f"{f.epss:.3f}" if f.epss is not None else "-"
        cvss = f"{f.cvss:.1f}" if f.cvss is not None else "-"
        rows.append(
            f"{f.priority:<4} {f.vuln_id[:20]:<20} {f.package[:28]:<28} {epss:>7} {cvss:>5}  "
            f"{'yes' if f.kev else '':<3}  {f.fixed_version or ''}"
        )
    return "\n".join(rows)


def _headline(s: dict) -> str:
    return (
        f"{s['total']} findings, {s['high_or_critical']} HIGH/CRITICAL by severity -> "
        f"{s['act_now']} need action now (P1 {s['by_priority']['P1']}, P2 {s['by_priority']['P2']})"
    )


def cmd_analyze(args) -> int:
    report, errors, summary = analyze(Path(args.file).read_bytes(), Enricher())
    print(_headline(summary))
    for e in errors:
        print(f"warning: {e}", file=sys.stderr)
    print(_table(report.findings, args.limit))
    return 0


def cmd_gate(args) -> int:
    fail_on = {p.strip().upper() for p in args.fail_on.split(",")}
    waived, problems = load_waivers(Path(args.waivers), date.today())
    report, errors, summary = analyze(Path(args.file).read_bytes(), Enricher())
    print(_headline(summary))
    for e in errors:
        print(f"warning: {e}", file=sys.stderr)
    blocking = [
        f
        for f in report.findings
        if f.priority in fail_on
        and (f.fixed_version or args.include_unfixed)
        and f.vuln_id not in waived
        and f.cve not in waived
    ]
    if blocking:
        print(f"\nFAIL: {len(blocking)} finding(s) in {','.join(sorted(fail_on))} with a fix available:")
        print(_table(blocking, len(blocking)))
    for p in problems:
        print(f"FAIL: {p}")
    if not blocking and not problems:
        print(f"PASS: no fixable {','.join(sorted(fail_on))} findings ({len(waived)} waived)")
    return 1 if blocking or problems else 0


def cmd_push(args) -> int:
    import boto3
    import httpx
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    body = Path(args.file).read_bytes()
    url = f"{args.api.rstrip('/')}/scans"
    params = {"name": args.name} if args.name else {}
    session = boto3.Session()
    req = AWSRequest(method="POST", url=str(httpx.URL(url, params=params)), data=body)
    # API Gateway IAM auth: sign with whatever credentials CI has (ideally short-lived, via GitHub OIDC)
    SigV4Auth(session.get_credentials(), "execute-api", args.region or session.region_name).add_auth(req)
    resp = httpx.post(req.url, content=body, headers=dict(req.headers), timeout=35)
    print(resp.text)
    return 0 if resp.is_success else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="vulnprio", description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    sub = parser.add_subparsers(required=True)

    p = sub.add_parser("analyze", help="rank a scan file and print the top findings")
    p.add_argument("file")
    p.add_argument("--limit", type=int, default=25)
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("gate", help="exit non-zero on fixable findings in the given tiers")
    p.add_argument("file")
    p.add_argument("--fail-on", default="P1,P2")
    p.add_argument("--waivers", default=".vulnprio-waivers")
    p.add_argument("--include-unfixed", action="store_true", help="also fail on findings with no fix yet")
    p.set_defaults(func=cmd_gate)

    p = sub.add_parser("push", help="upload a scan to a deployed vulnprio API (SigV4)")
    p.add_argument("file")
    p.add_argument("--api", required=True)
    p.add_argument("--name")
    p.add_argument("--region")
    p.set_defaults(func=cmd_push)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ParseError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
