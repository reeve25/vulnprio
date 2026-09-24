"""Build the static GitHub Pages demo: dashboard + precomputed JSON from samples/.

Usage: uv run python scripts/build_demo.py [out_dir]   (default: site/)
Enriches against live KEV/EPSS, so the demo reflects today's exploit data.
"""

import json
import shutil
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from vulnprio.enrich import Enricher, exploit_data_errors
from vulnprio.scoring import analyze

ROOT = Path(__file__).resolve().parent.parent
# SARIF duplicates the nginx Trivy JSON (same scan, different format), so it's left out of the demo.
SAMPLES = [
    ("solr:8.11.0", "trivy_solr_8.11.0.json.gz"),
    ("nginx:1.21", "trivy_nginx_1.21.json.gz"),
    ("node:16-bullseye-slim", "trivy_node_16-bullseye-slim.json.gz"),
    ("python:3.9-slim-bullseye (Trivy)", "trivy_python_3.9-slim-bullseye.json.gz"),
    ("python:3.9-slim-bullseye (Grype)", "grype_python_3.9-slim-bullseye.json.gz"),
]


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "site"
    shutil.rmtree(out, ignore_errors=True)
    shutil.copytree(ROOT / "src" / "vulnprio" / "site", out)
    (out / "data").mkdir()
    enricher = Enricher()
    index = []
    for i, (name, file) in enumerate(SAMPLES):
        report, errors, summary = analyze((ROOT / "samples" / file).read_bytes(), enricher)
        if errors:
            print(f"{file}: enrichment errors {errors}", file=sys.stderr)
        if exploit_data_errors(errors):
            return 1  # never publish rankings without KEV/EPSS; missing NVD backfill only touches P3
        scan_id = f"demo-{i}"
        meta = {
            "scan_id": scan_id,
            "name": name,
            "artifact": report.artifact,
            "format": report.format,
            "source_file": f"samples/{file}",
            "summary": summary,
        }
        index.append(meta)
        doc = {**meta, "findings": [asdict(f) for f in report.findings]}
        (out / "data" / f"{scan_id}.json").write_text(json.dumps(doc, separators=(",", ":")))
        s = summary
        print(f"{name}: {s['total']} findings, {s['high_or_critical']} high/crit -> {s['act_now']} act now")
    (out / "data" / "index.json").write_text(
        json.dumps(
            {
                "generated_at": datetime.now(UTC).isoformat(timespec="minutes"),
                "kev_catalog_version": enricher.kev_version,
                "scans": index,
            },
            indent=1,
        )
    )
    (out / ".nojekyll").touch()
    return 0


if __name__ == "__main__":
    sys.exit(main())
