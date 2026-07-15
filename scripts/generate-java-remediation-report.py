#!/usr/bin/env python3
"""
generate-java-remediation-report.py

Generates a focused, human-readable Markdown report that lists **only** the
Java source code changes produced by the AI auto-remediation step.

OUTPUT
------
    reports/JAVA_VULNERABILITY_REMEDIATION_REPORT.md

For every Java file changed by the AI rewriter, the report shows:
  - The vulnerability that was remediated (title / severity / CWE / OWASP).
  - The **previous** code (lines removed by the patch).
  - The **after** code (lines added by the patch).
  - A short explanation of what changed and why it's safer.

The script is a pure aggregator: it does NOT touch source files, does NOT
call the LLM, and does NOT push anything. It only formats artefacts
already produced earlier in the pipeline.

INPUT (paths configurable via --reports, default ./reports)
-----------------------------------------------------------
    ai-patch.diff              - unified diff produced by ai-remediation.py
    remediation-report.json    - structured remediation output (per-fix
                                 CWE / OWASP / explanation / status)
    security-review.json       - structured security review (per-finding
                                 title, severity, file, line, cwe, owasp)
    changed-files.txt          - newline-separated list of changed files
    git-diff-stat.txt          - `git diff --stat` of the patch
    remediation-summary.md     - short remediation summary (fallback only)

EXIT
----
    0 on success, non-zero on fatal I/O error only. The script tolerates
    missing optional inputs and emits a "no Java changes" report rather
    than failing the workflow.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------- #
# Constants & helpers
# --------------------------------------------------------------------- #

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

STATUS_LABEL = {
    "applied": "Applied",
    "skipped_build": "Skipped — due to build breakage",
    "skipped_residual": "Skipped — see Residual Risks",
    None: "Applied (no structured metadata)",
}


def _read_text(p: Path) -> str:
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def _read_json(p: Path) -> Any:
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _truncate(s: str, n: int = 200) -> str:
    s = (s or "").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _na(v: Any, default: str = "N/A") -> str:
    if v is None or v == "":
        return default
    return str(v)


# --------------------------------------------------------------------- #
# Diff parsing
# --------------------------------------------------------------------- #


# Matches a unified diff file header, capturing the two paths.
_DIFF_FILE_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)\s*$")


def _parse_diff_per_file(patch_text: str) -> dict[str, list[str]]:
    """Return ``{file_path: [hunk_lines, ...]}`` for every file in the
    diff. Each hunk_lines entry is the raw list of lines belonging to
    that file's section of the diff (including the ``diff --git``,
    ``---``, ``+++``, and ``@@`` lines)."""
    if not patch_text:
        return {}

    out: dict[str, list[str]] = {}
    current: list[str] | None = None
    current_path: str | None = None

    for ln in patch_text.splitlines():
        m = _DIFF_FILE_RE.match(ln)
        if m:
            # New file section. Prefer the "b/" path (post-rename target).
            current_path = m.group(2) or m.group(1)
            current = []
            out.setdefault(current_path, []).extend(current)
            current = out[current_path]
            continue
        if current is not None:
            current.append(ln)
    return out


def _split_hunk_before_after(hunk_lines: list[str]) -> tuple[str, str, list[str]]:
    """Walk a single file's diff lines and return ``(before, after, hunks)``.

    ``before`` and ``after`` are newline-joined strings of removed / added
    code lines (without the leading ``-`` / ``+``). ``hunks`` is the list of
    ``@@ ... @@`` header lines, useful as a location hint in the report.
    """
    before: list[str] = []
    after: list[str] = []
    hunks: list[str] = []
    for ln in hunk_lines:
        if ln.startswith("---") or ln.startswith("+++") or ln.startswith("diff --git"):
            continue
        if ln.startswith("@@"):
            hunks.append(ln)
            continue
        if ln.startswith("-"):
            before.append(ln[1:])
        elif ln.startswith("+"):
            after.append(ln[1:])
    return (
        "\n".join(before).strip("\n"),
        "\n".join(after).strip("\n"),
        hunks,
    )


# --------------------------------------------------------------------- #
# Finding lookup
# --------------------------------------------------------------------- #


def _build_finding_index(security_review: dict) -> list[dict]:
    """Return the list of findings from a security-review dict, sorted
    by severity. The security review may store findings under
    ``findings`` or ``vulnerabilities`` depending on producer."""
    raw = (
        (security_review or {}).get("findings")
        or (security_review or {}).get("vulnerabilities")
        or []
    )
    if not isinstance(raw, list):
        return []
    return sorted(
        raw,
        key=lambda f: (
            SEVERITY_ORDER.get((f.get("severity") or "INFO").upper(), 9),
            str(f.get("id", "")),
        ),
    )


def _match_finding(
    findings: list[dict],
    java_path: str,
    fixes_for_file: list[dict] | None = None,
) -> dict | None:
    """Pick the most relevant finding/fix for a given Java file path.

    Preference order:
      1. A fix in ``fixes_for_file`` with a matching ``finding_id`` that
         points to a finding whose ``file`` is this path.
      2. A fix with the same ``file``.
      3. A finding whose ``file`` matches the path (with or without
         leading ``src/main/java/``).
    """
    if fixes_for_file:
        for fx in fixes_for_file:
            fid = fx.get("finding_id") or fx.get("id")
            if fid:
                for f in findings:
                    if str(f.get("id")) == str(fid):
                        return {"finding": f, "fix": fx}
    if fixes_for_file:
        for fx in fixes_for_file:
            if (fx.get("file") or "").lstrip("./") == java_path.lstrip("./"):
                return {"finding": None, "fix": fx}

    norm = java_path.lstrip("./")
    for f in findings:
        f_file = (f.get("file") or "").lstrip("./")
        if not f_file:
            continue
        if f_file == norm or f_file.endswith("/" + norm) or norm.endswith("/" + f_file):
            return {"finding": f, "fix": None}
    return None


# --------------------------------------------------------------------- #
# Markdown rendering
# --------------------------------------------------------------------- #


def _render_header(ctx: dict) -> list[str]:
    return [
        "# 🛡️ Java Vulnerability Remediation Report",
        "",
        "_Generated by `scripts/generate-java-remediation-report.py` at "
        f"{_now_iso()}._",
        "",
        f"- **Repository / Branch:** `{ctx['repository']}` @ `{ctx['branch']}`",
        f"- **Triggered by:** `{ctx['trigger']}`",
        f"- **Pipeline run:** `{ctx['run_id']}` (workflow: `{ctx['workflow']}`)",
        f"- **Commit SHA:** `{ctx['commit']}`",
        "",
        "This report is dedicated to **Java source code only** and shows the",
        "previous (vulnerable) code alongside the after (remediated) code",
        "for every change made by the AI auto-remediation step.",
        "",
        "---",
        "",
    ]


def _render_executive_summary(java_changes: list[dict], all_files: list[str]) -> list[str]:
    out = ["## 1. Executive Summary", ""]
    out.append("| Metric | Value |")
    out.append("| --- | --- |")
    out.append(f"| Java source files changed | **{len(java_changes)}** |")
    out.append(f"| Total files changed in this run | **{len(all_files)}** |")
    if java_changes:
        sevs: dict[str, int] = {}
        for ch in java_changes:
            sev = (ch.get("severity") or "INFO").upper()
            sevs[sev] = sevs.get(sev, 0) + 1
        sev_summary = " · ".join(
            f"{sevs.get(s, 0)} {s}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        )
        out.append(f"| Severities remediated | {sev_summary} |")
    out.append("")
    if not java_changes:
        out.append(
            "> ⚠️ **No Java source files were changed in this run.** "
            "The AI rewriter either left every Java file untouched or "
            "only modified non-Java files (e.g. `Dockerfile`, `pom.xml`)."
        )
        out.append("")
    out.append("---")
    out.append("")
    return out


def _render_file_section(idx: int, change: dict) -> list[str]:
    f = change["file"]
    sev = (change.get("severity") or "INFO").upper()
    cwe = change.get("cwe") or "N/A"
    owasp = change.get("owasp") or "N/A"
    title = change.get("title") or "Java source change"
    status = change.get("status_label") or "Applied"
    explanation = change.get("explanation") or "_No explanation recorded._"
    benefit = change.get("security_benefit") or "_No benefit description recorded._"
    hunk_headers = change.get("hunks") or []
    finding_id = change.get("finding_id") or "—"

    out: list[str] = []
    out.append(f"## {idx}. `{f}`")
    out.append("")
    out.append(f"**Vulnerability:** {title}  ")
    out.append(f"**Finding ID:** `{finding_id}`  ")
    out.append(f"**Severity:** `{sev}`  ")
    out.append(f"**CWE:** `{cwe}`  ")
    out.append(f"**OWASP:** `{owasp}`  ")
    out.append(f"**Status:** {status}  ")
    if hunk_headers:
        # Cap at 3 hunk headers to keep the section compact.
        shown = hunk_headers[:3]
        more = len(hunk_headers) - len(shown)
        hint = "  ".join(f"`{h}`" for h in shown)
        if more > 0:
            hint += f" … (+{more} more)"
        out.append(f"**Locations (diff hunks):** {hint}  ")
    out.append("")

    out.append("### ❌ Previous Code (Vulnerable)")
    out.append("")
    out.append("```java")
    out.append(change["before"] if change["before"] else "_No removed lines captured by the diff._")
    out.append("```")
    out.append("")

    out.append("### ✅ After Code (Remediated)")
    out.append("")
    out.append("```java")
    out.append(change["after"] if change["after"] else "_No added lines captured by the diff._")
    out.append("```")
    out.append("")

    out.append("### 📖 Explanation of the Change")
    out.append("")
    out.append(_truncate(explanation, 800))
    out.append("")

    out.append("### 🔐 Security Benefit")
    out.append("")
    out.append(_truncate(benefit, 600))
    out.append("")
    out.append("---")
    out.append("")
    return out


def _render_footer() -> list[str]:
    return [
        "_End of Java Vulnerability Remediation Report._",
        "",
    ]


# --------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------- #


def _load_context(reports: Path) -> dict:
    patch = _read_text(reports / "ai-patch.diff")
    rem_report = _read_json(reports / "remediation-report.json") or {}
    sec_review = _read_json(reports / "security-review.json") or {}

    changed_raw = _read_text(reports / "changed-files.txt")
    all_changed = [ln.strip() for ln in changed_raw.splitlines() if ln.strip()]

    diff_by_file = _parse_diff_per_file(patch)

    findings = _build_finding_index(sec_review)
    fixes = rem_report.get("fixes") if isinstance(rem_report, dict) else None
    if not isinstance(fixes, list):
        fixes = []

    # GH env (best-effort, defaults are fine for local runs).
    repository = os.environ.get("GITHUB_REPOSITORY", "local/repo")
    branch = os.environ.get("GITHUB_REF_NAME", "local")
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    workflow = os.environ.get("GITHUB_WORKFLOW", "local")
    commit = os.environ.get("GITHUB_SHA", "local")
    event = os.environ.get("GITHUB_EVENT_NAME", "local")
    trigger = {
        "push": "push",
        "pull_request": "pull_request",
        "workflow_dispatch": "workflow_dispatch",
    }.get(event, event)

    return {
        "reports_dir": reports,
        "patch": patch,
        "diff_by_file": diff_by_file,
        "all_changed": all_changed,
        "findings": findings,
        "fixes": fixes,
        "repository": repository,
        "branch": branch,
        "run_id": run_id,
        "workflow": workflow,
        "commit": commit,
        "trigger": trigger,
    }


def _collect_java_changes(ctx: dict) -> list[dict]:
    changes: list[dict] = []
    seen: set[str] = set()

    # Java files present in the diff are the primary signal.
    candidate_paths: list[str] = []
    for path in ctx["diff_by_file"].keys():
        if path.endswith(".java"):
            candidate_paths.append(path)
            seen.add(path)

    # Also pull in any *.java paths listed in changed-files.txt that the
    # diff parser might have missed (defensive).
    for path in ctx["all_changed"]:
        if path.endswith(".java") and path not in seen:
            candidate_paths.append(path)
            seen.add(path)

    for path in candidate_paths:
        hunk_lines = ctx["diff_by_file"].get(path) or []
        before, after, hunks = _split_hunk_before_after(hunk_lines)
        fixes_for_file = [fx for fx in ctx["fixes"] if (fx.get("file") or "").lstrip("./") == path.lstrip("./")]
        match = _match_finding(ctx["findings"], path, fixes_for_file) or {}

        finding = match.get("finding") or {}
        fix = match.get("fix") or {}

        # Prefer structured remediation data, fall back to the security review.
        severity = (fix.get("severity") or finding.get("severity") or "INFO")
        cwe = fix.get("cwe") or finding.get("cwe")
        owasp = fix.get("owasp") or finding.get("owasp")
        title = finding.get("title") or fix.get("description") or fix.get("explanation") or "Java source change"
        status = fix.get("status") or "applied"
        explanation = fix.get("explanation") or finding.get("summary") or finding.get("suggested_fix") or ""
        benefit = fix.get("security_benefit") or finding.get("impact") or ""
        finding_id = finding.get("id") or fix.get("finding_id") or fix.get("id")

        # If both before and after are empty, this is a mode-only / no-op
        # change for Java; still record it but flag the status.
        if not before and not after:
            status = "skipped_residual"

        changes.append({
            "file": path,
            "title": title,
            "severity": severity,
            "cwe": cwe,
            "owasp": owasp,
            "status": status,
            "status_label": STATUS_LABEL.get(status, status),
            "explanation": explanation,
            "security_benefit": benefit,
            "hunks": hunks,
            "before": before or "",
            "after": after or "",
            "finding_id": finding_id,
        })

    # Sort by severity (CRITICAL first), then by file path for determinism.
    changes.sort(
        key=lambda c: (
            SEVERITY_ORDER.get((c.get("severity") or "INFO").upper(), 9),
            c["file"],
        )
    )
    return changes


def build_report(ctx: dict) -> str:
    java_changes = _collect_java_changes(ctx)
    parts: list[str] = []
    parts.extend(_render_header(ctx))
    parts.extend(_render_executive_summary(java_changes, ctx["all_changed"]))
    parts.append("## 2. Java Source Code Changes (Before / After)")
    parts.append("")
    if not java_changes:
        parts.append("_No Java source files were modified in this run._")
        parts.append("")
    else:
        parts.append(
            "Each section below corresponds to one remediated Java file. "
            "Compare the **Previous Code** (vulnerable) with the **After "
            "Code** (remediated) to understand the change."
        )
        parts.append("")
        for i, ch in enumerate(java_changes, start=1):
            parts.extend(_render_file_section(i, ch))
    parts.extend(_render_footer())
    return "\n".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1] if __doc__ else "")
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("reports/JAVA_VULNERABILITY_REMEDIATION_REPORT.md"),
    )
    args = ap.parse_args()

    if not args.reports.exists():
        print(f"ERROR: reports dir {args.reports} does not exist", file=sys.stderr)
        return 1

    ctx = _load_context(args.reports)
    report = build_report(ctx)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report, encoding="utf-8")
    print(f"Java vulnerability remediation report written to {args.out}")

    # Also write the same content to $GITHUB_STEP_SUMMARY so it appears on
    # the GitHub Actions run summary tab. No-op when the env var is unset
    # (e.g. local runs).
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as fh:
                fh.write(report + "\n")
        except OSError as exc:
            print(
                f"::warning::Could not append to GITHUB_STEP_SUMMARY ({exc}).",
                file=sys.stderr,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
