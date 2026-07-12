#!/usr/bin/env python3
"""
generate-sonar-report.py

Calls the SonarCloud /api/issues/search endpoint and writes:
  - <output-dir>/sonar-report.json : full list of issues (up to 500 per page)
  - <output-dir>/sonar-report.txt  : human-readable summary, sorted by severity

Also fetches /api/qualitygates/project_status and /api/measures/component for
context, and embeds the quality gate and key metrics in the JSON.

Required env:
  SONAR_TOKEN         - SonarCloud account token
  SONAR_HOST_URL      - e.g. https://sonarcloud.io
  SONAR_PROJECT_KEY   - the project key

Optional env:
  PAGE_SIZE           - default 500
"""
import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from pathlib import Path

SEVERITY_RANK = {"BLOCKER": 5, "CRITICAL": 4, "MAJOR": 3, "MINOR": 2, "INFO": 1}

METRICS = (
    "bugs,vulnerabilities,security_hotspots,code_smells,"
    "duplicated_lines_density,coverage,reliability_rating,security_rating,"
    "maintainability_rating,technical_debt,open_issues,new_vulnerabilities,"
    "new_coverage"
)


def _http_get_json(url: str, token: str) -> dict | None:
    """GET a SonarCloud API endpoint and return JSON, or None on failure."""
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except Exception as exc:  # noqa: BLE001
        print(f"WARN: GET {url} failed: {exc}", file=sys.stderr)
        return None


def fetch_issues(host: str, project_key: str, token: str, page_size: int) -> list:
    issues: list = []
    for page in range(1, 10):  # 10 pages * 500 = 5000 issues cap
        url = (
            f"{host}/api/issues/search"
            f"?projectKeys={urllib.parse.quote(project_key, safe='')}"
            f"&types=VULNERABILITY,CODE_SMELL,BUG,SECURITY_HOTSPOT"
            f"&ps={page_size}&p={page}"
        )
        data = _http_get_json(url, token)
        if not data:
            break
        batch = data.get("issues", []) or []
        if not batch:
            break
        issues.extend(batch)
        if len(batch) < page_size:
            break
    return issues


def fetch_quality_gate(host: str, project_key: str, token: str) -> str:
    data = _http_get_json(
        f"{host}/api/qualitygates/project_status?projectKey={urllib.parse.quote(project_key, safe='')}",
        token,
    )
    if data:
        return (data.get("projectStatus", {}) or {}).get("status", "ERROR")
    return "UNKNOWN"


def fetch_measures(host: str, project_key: str, token: str) -> dict:
    data = _http_get_json(
        f"{host}/api/measures/component?component={urllib.parse.quote(project_key, safe='')}&metricKeys={METRICS}",
        token,
    )
    out: dict = {}
    if data:
        for item in (data.get("component", {}) or {}).get("measures", []) or []:
            metric = item.get("metric")
            if metric:
                out[metric] = item.get("value", item.get("bestValue"))
    return out


def _issue_to_finding(it: dict) -> dict:
    component = it.get("component", "") or ""
    file_path = component.split(":", 1)[1] if ":" in component else component
    return {
        "key": it.get("key"),
        "rule": it.get("rule"),
        "severity": (it.get("severity") or "INFO").upper(),
        "type": it.get("type"),
        "status": it.get("status"),
        "message": it.get("message", ""),
        "file": file_path,
        "line": it.get("line"),
        "project": it.get("project"),
        "creationDate": it.get("creationDate"),
        "updateDate": it.get("updateDate"),
        "tags": it.get("tags", []) or [],
    }


def write_text_summary(findings: list, metrics: dict, qg_status: str, path: Path) -> None:
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    lines: list[str] = [
        "SonarCloud Issue Summary",
        "========================",
        "",
        f"Quality Gate : {qg_status}",
        f"Bugs         : {metrics.get('bugs', 'N/A')}",
        f"Vulnerabilities: {metrics.get('vulnerabilities', 'N/A')}",
        f"Security Hotspots: {metrics.get('security_hotspots', 'N/A')}",
        f"Code Smells  : {metrics.get('code_smells', 'N/A')}",
        f"Coverage     : {metrics.get('coverage', 'N/A')}%",
        f"Duplication  : {metrics.get('duplicated_lines_density', 'N/A')}%",
        f"Tech Debt    : {metrics.get('technical_debt', 'N/A')}",
        "",
        f"Total issues exported: {len(findings)}",
        "By severity:",
    ]
    for sev in sorted(by_sev, key=lambda s: SEVERITY_RANK.get(s, 0), reverse=True):
        lines.append(f"  {sev:9s} {by_sev[sev]}")
    lines.append("")
    lines.append("Top issues (sorted by severity, then by file):")
    lines.append("----------------------------------------------")
    sorted_findings = sorted(
        findings,
        key=lambda f: (-SEVERITY_RANK.get(f["severity"], 0), f.get("file") or "", f.get("line") or 0),
    )
    for f in sorted_findings[:50]:
        where = f["file"]
        if f.get("line"):
            where = f"{where}:{f['line']}"
        lines.append(
            f"[{f['severity']:8s}] {f['type']:18s} {f.get('rule', ''):30s} {where}"
        )
        if f.get("message"):
            lines.append(f"            -> {f['message'][:120]}")
    if len(sorted_findings) > 50:
        lines.append("")
        lines.append(f"... and {len(sorted_findings) - 50} more (see sonar-report.json)")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--output-dir", required=True, type=Path)
    p.add_argument("--host", default=os.environ.get("SONAR_HOST_URL", "https://sonarcloud.io"))
    p.add_argument("--project-key", default=os.environ.get("SONAR_PROJECT_KEY", ""))
    p.add_argument("--token", default=os.environ.get("SONAR_TOKEN", ""))
    p.add_argument("--page-size", type=int, default=int(os.environ.get("PAGE_SIZE", "500")))
    args = p.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    if not args.token or not args.project_key:
        print("WARN: SONAR_TOKEN or SONAR_PROJECT_KEY not set; writing stub report.", file=sys.stderr)
        stub = {
            "status": "SKIPPED",
            "projectKey": args.project_key,
            "host": args.host,
            "qualityGate": "UNKNOWN",
            "metrics": {},
            "issues": [],
        }
        (args.output_dir / "sonar-report.json").write_text(json.dumps(stub, indent=2), encoding="utf-8")
        (args.output_dir / "sonar-report.txt").write_text(
            "SonarCloud report skipped (missing SONAR_TOKEN or SONAR_PROJECT_KEY)\n",
            encoding="utf-8",
        )
        return 0

    print(f"Fetching SonarCloud issues for {args.project_key} from {args.host}", file=sys.stderr)
    issues = fetch_issues(args.host, args.project_key, args.token, args.page_size)
    qg_status = fetch_quality_gate(args.host, args.project_key, args.token)
    metrics = fetch_measures(args.host, args.project_key, args.token)

    findings = [_issue_to_finding(it) for it in issues]
    findings.sort(key=lambda f: (-SEVERITY_RANK.get(f["severity"], 0), f.get("file") or "", f.get("line") or 0))

    report = {
        "status": "OK",
        "projectKey": args.project_key,
        "host": args.host,
        "qualityGate": qg_status,
        "metrics": metrics,
        "issues": findings,
    }
    (args.output_dir / "sonar-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_text_summary(findings, metrics, qg_status, args.output_dir / "sonar-report.txt")

    print(
        f"Wrote {len(findings)} issues to {args.output_dir}/sonar-report.json",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
