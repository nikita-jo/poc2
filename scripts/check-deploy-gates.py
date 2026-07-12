#!/usr/bin/env python3
"""
check-deploy-gates.py

Validates the post-remediation state of the pipeline and writes a JSON
result file the deploy job consumes.

Required inputs (paths are configurable via flags):
  --coverage-summary    Path to JaCoCo coverage summary CSV (or jacoco.xml)
  --sonar-report        Path to sonar-report-after-fix.json
  --trivy-report        Path to trivy-report-after-fix.json
  --remediation-report  Path to remediation-report.json
  --rebuild-result      Path to a file whose presence indicates a successful
                        rebuild (e.g. target/.rebuild-ok)
  --output              Where to write the gate result JSON

Required env (or defaults):
  MIN_COVERAGE                 int percent, default 70
  ALLOW_CRITICAL               bool, default False
  ALLOW_HIGH                   bool, default False
  REQUIRED_QUALITY_GATE        default "OK"

Exit code:
  0  = all gates passed
  1  = at least one gate failed (gates still written to --output)
"""
import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def _parse_jacoco_coverage(path: Path) -> float | None:
    """Return overall line coverage % from a JaCoCo XML or CSV summary."""
    if not path.exists():
        return None
    if path.suffix == ".xml":
        try:
            root = ET.parse(path).getroot()
            for counter in root.iter("counter"):
                if counter.get("type") == "LINE":
                    missed = int(counter.get("missed", 0))
                    covered = int(counter.get("covered", 0))
                    total = missed + covered
                    return round(covered / total * 100, 2) if total else None
        except Exception:  # noqa: BLE001
            return None
    # CSV: expect a row with header `LINE,%instructions,...` style — fall back
    # to a generic regex for any "XX%" pattern on a "Total" line.
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:  # noqa: BLE001
        return None
    m = re.search(r"Total.*?(\d{1,3}(?:\.\d+)?)\s*%", text, re.IGNORECASE | re.DOTALL)
    if m:
        return float(m.group(1))
    return None


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--coverage-summary", type=Path, default=Path("reports/coverage-summary.csv"))
    p.add_argument("--sonar-report", type=Path, default=Path("reports/sonar-report-after-fix.json"))
    p.add_argument("--trivy-report", type=Path, default=Path("reports/trivy-report-after-fix.json"))
    p.add_argument("--remediation-report", type=Path, default=Path("reports/remediation-report.json"))
    p.add_argument("--rebuild-result", type=Path, default=Path("target/.rebuild-ok"))
    p.add_argument("--output", type=Path, default=Path("reports/deploy-gates.json"))
    args = p.parse_args()

    min_coverage = int(os.environ.get("MIN_COVERAGE", "70"))
    allow_critical = os.environ.get("ALLOW_CRITICAL", "false").lower() == "true"
    allow_high = os.environ.get("ALLOW_HIGH", "false").lower() == "true"
    required_qg = os.environ.get("REQUIRED_QUALITY_GATE", "OK")

    gates: list[dict] = []

    # 1) Build success
    build_ok = args.rebuild_result.exists()
    gates.append({
        "name": "build_succeeded",
        "expected": True,
        "actual": build_ok,
        "passed": build_ok,
    })

    # 2) Coverage threshold
    coverage_pct = _parse_jacoco_coverage(args.coverage_summary)
    coverage_ok = coverage_pct is not None and coverage_pct >= min_coverage
    gates.append({
        "name": "coverage_threshold",
        "expected": f">= {min_coverage}%",
        "actual": coverage_pct,
        "passed": coverage_ok,
    })

    # 3) SonarCloud quality gate
    sonar = _load_json(args.sonar_report)
    qg = sonar.get("qualityGate", "UNKNOWN")
    sonar_ok = qg == required_qg
    gates.append({
        "name": "sonar_quality_gate",
        "expected": required_qg,
        "actual": qg,
        "passed": sonar_ok,
    })

    # 4) SonarCloud no new vulnerabilities introduced (re-scan should not have
    #    more vulnerabilities than the pre-fix scan; we don't have the pre-fix
    #    in the gate step, so we just check that the current scan has zero).
    new_vulns = sonar.get("metrics", {}).get("vulnerabilities", "0")
    try:
        new_vulns_n = int(new_vulns)
    except (TypeError, ValueError):
        new_vulns_n = -1
    vulns_ok = new_vulns_n == 0
    gates.append({
        "name": "no_remaining_vulnerabilities",
        "expected": 0,
        "actual": new_vulns_n,
        "passed": vulns_ok,
    })

    # 5) Trivy severity
    trivy = _load_json(args.trivy_report)
    findings = trivy if isinstance(trivy, list) else trivy.get("findings", [])
    critical = sum(1 for f in findings if (f.get("severity") or "").upper() == "CRITICAL")
    high = sum(1 for f in findings if (f.get("severity") or "").upper() == "HIGH")

    critical_ok = (critical == 0) or allow_critical
    high_ok = (high == 0) or allow_high

    gates.append({
        "name": "no_critical_trivy",
        "expected": "0 (allow_critical=%s)" % allow_critical,
        "actual": critical,
        "passed": critical_ok,
    })
    gates.append({
        "name": "no_high_trivy",
        "expected": "0 (allow_high=%s)" % allow_high,
        "actual": high,
        "passed": high_ok,
    })

    # 6) AI remediation completed
    remediation = _load_json(args.remediation_report)
    remediation_ok = bool(remediation.get("fixes")) or remediation.get("status") in {"OK", "SKIPPED"}
    gates.append({
        "name": "ai_remediation_completed",
        "expected": True,
        "actual": remediation.get("status", "MISSING"),
        "passed": remediation_ok,
    })

    all_passed = all(g["passed"] for g in gates)
    result = {
        "all_passed": all_passed,
        "deploy_recommended": all_passed,
        "gates": gates,
        "environment": os.environ.get("DEPLOY_ENV", "dev"),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(json.dumps(result, indent=2))
    if not all_passed:
        failed = [g["name"] for g in gates if not g["passed"]]
        print(f"\n::error::Deploy gate(s) FAILED: {', '.join(failed)}", file=sys.stderr)
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
