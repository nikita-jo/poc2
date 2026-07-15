#!/usr/bin/env python3
"""
generate-remediation-report.py

Consolidates the output of every available pipeline stage (SonarQube,
Trivy filesystem + image, dependency scan, secret scan, IaC scan,
container scan, SAST, code quality, AI security review, AI auto-
remediation, git diff) into a single enterprise-grade Markdown
audit document:

    reports/remediation-report.md

This is a pure aggregator. It never modifies the input artefacts,
never edits source code, never shells out to git/gh/Trivy, and never
calls any LLM. Stages that did not produce an artefact on disk are
reported as `_not available in this run_` so the document stays
honest when the pipeline is partial.

OUTPUT FORMAT
-------------
The report layout mirrors the schema used by the `remediation-agent`
Claude Code subagent (see `.claude/agents/remediation-agent.md`), so a
human reviewer sees the same section structure regardless of whether
the fixes were produced by that agent or by this pipeline's
deterministic + LLM rewriter (`scripts/ai-remediation.py`):

  1. # Remediation Summary
  2. # Changes Made
  3. # Changes That Remained — Due To Build Breakage
  4. # Files Referenced
  5. # Vulnerability Remediations   (one subsection per finding)
  6. # Security Improvements
  7. # Residual Risks
  8. # Secure Coding Recommendations

IMPORTANT — data-availability caveat: the `remediation-agent` spec
assumes an agent that edits files itself and therefore knows, per
finding, the exact compiler error that blocked a fix. This script
only *aggregates artefacts already on disk* — it does not compile
anything. So "Changes That Remained — Due To Build Breakage" and the
per-finding "Build Impact" field are populated from
`remediation-report.json` **only if** the upstream step
(`ai-remediation.py`) recorded that data there. If it didn't, those
fields are honestly reported as `_not available in this run_` rather
than guessed.

Required input (paths are configurable via --reports, default
./reports):
    security-review.json    - the structured security review
    security-review.md      - the human-readable review
    trivy-report.json       - aggregated Trivy findings
    trivy-report.txt        - text rendering
    sonar-report.json       - SonarCloud summary
    sonar-report.txt        - SonarCloud text rendering
    changed-files.txt       - files changed by the remediation
    git-diff-stat.txt       - `git diff --stat` of those changes
    ai-patch.diff           - unified diff emitted by the rewriter
    remediation-summary.md  - the short remediation summary
    remediation-report.json - structured remediation output (optional
                               richer per-fix data: status, cwe, owasp,
                               build_impact, compiler_error, etc.)
    llm-prompt.txt          - prompt sent to the LLM
    llm-response.txt        - raw LLM response (if any)
    trivy-fs.raw.json       - raw Trivy fs scan (optional)
    trivy-fs.sarif          - Trivy fs SARIF (optional)
    trivy-image.raw.json    - raw Trivy image scan (optional)
    trivy-image.sarif       - Trivy image SARIF (optional)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------- #

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


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


def _na(v: Any, default: str = "_not available in this run_") -> str:
    if v is None or v == "":
        return default
    return str(v)


def _diff_hunk_for_file(patch_text: str, target_file: str) -> str:
    """Return the subset of a unified diff that belongs to a given file.

    Empty string if there is no diff hunk for that file."""
    if not patch_text:
        return ""
    lines = patch_text.splitlines()
    out: list[str] = []
    capture = False
    for ln in lines:
        if ln.startswith("diff --git "):
            capture = target_file in ln
        if capture:
            out.append(ln)
    return "\n".join(out)


def _split_hunk_before_after(hunk: str) -> tuple[str, str]:
    """Best-effort split of a unified diff hunk into 'before' (removed
    lines) and 'after' (added lines) snippets. Falls back to empty
    strings if the hunk has no +/- body lines."""
    before, after = [], []
    for ln in hunk.splitlines():
        if ln.startswith("---") or ln.startswith("+++"):
            continue
        if ln.startswith("-"):
            before.append(ln[1:])
        elif ln.startswith("+"):
            after.append(ln[1:])
    return "\n".join(before).strip("\n"), "\n".join(after).strip("\n")


def _finding_sort_key(f: dict) -> tuple:
    sev = (f.get("severity") or "INFO").upper()
    return (SEVERITY_ORDER.get(sev, 9), str(f.get("id", "")))


def _lang_for_file(path: str) -> str:
    if path.endswith(".java"):
        return "java"
    if path.endswith((".yml", ".yaml")):
        return "yaml"
    if path.endswith(".xml"):
        return "xml"
    if path.endswith(".properties"):
        return "properties"
    if path == "Dockerfile":
        return "dockerfile"
    return ""


# --------------------------------------------------------------------- #
# Context loading
# --------------------------------------------------------------------- #


def _load_ctx(reports: Path) -> dict:
    sr = _read_json(reports / "security-review.json") or {}
    trivy = _read_json(reports / "trivy-report.json") or []
    if isinstance(trivy, dict):
        trivy = trivy.get("findings", []) or []
    sonar = _read_json(reports / "sonar-report.json") or {}
    rem_report = _read_json(reports / "remediation-report.json") or {}

    patch = _read_text(reports / "ai-patch.diff")
    changed_raw = _read_text(reports / "changed-files.txt")
    changed = [ln.strip() for ln in changed_raw.splitlines() if ln.strip()]
    stat = _read_text(reports / "git-diff-stat.txt")
    rem_sum = _read_text(reports / "remediation-summary.md")
    llm_prompt = _read_text(reports / "llm-prompt.txt")
    llm_response = _read_text(reports / "llm-response.txt")

    # Parse fix count from the short summary (fallback only)
    fix_count = 0
    m = re.search(r"Safe fixes applied:\s*(\d+)", rem_sum)
    if m:
        fix_count = int(m.group(1))

    # Prefer structured per-fix data from remediation-report.json if the
    # upstream step provides it (richer: status, build_impact,
    # compiler_error, cwe, owasp, explanation, security_benefit).
    # Otherwise fall back to a heuristic list derived from the diff.
    structured_fixes = rem_report.get("fixes") if isinstance(rem_report, dict) else None

    fixes: list[dict] = []
    if isinstance(structured_fixes, list) and structured_fixes:
        for sf in structured_fixes:
            fixes.append({
                "file": sf.get("file", ""),
                "rule": sf.get("rule", sf.get("rule_id", "code-change")),
                "description": sf.get("description", sf.get("explanation", "")),
                "status": sf.get("status"),              # e.g. "applied" / "skipped_build" / "skipped_residual"
                "build_impact": sf.get("build_impact"),
                "compiler_error": sf.get("compiler_error"),
                "cwe": sf.get("cwe"),
                "owasp": sf.get("owasp"),
                "explanation": sf.get("explanation"),
                "security_benefit": sf.get("security_benefit"),
                "finding_id": sf.get("finding_id", sf.get("id")),
            })
    else:
        for f in changed:
            hunk = _diff_hunk_for_file(patch, f)
            if not hunk:
                continue
            rule = "code-change"
            if f == "pom.xml":
                rule = "outdated-dependency"
            elif f == "Dockerfile":
                rule = "outdated-base-image"
            # Skip diff plumbing lines (diff --git / --- / +++ / @@) and
            # prefer the first added ('+') content line — that's the fixed
            # version — falling back to a removed ('-') line only if the
            # hunk has no additions, so the fallback description isn't just
            # a raw diff header or the old vulnerable line.
            added_line, removed_line = "", ""
            for ln in hunk.splitlines():
                if ln.startswith(("diff --git", "---", "+++", "@@", "index ")):
                    continue
                if ln.startswith("+") and not added_line:
                    added_line = ln[1:].strip()
                elif ln.startswith("-") and not removed_line:
                    removed_line = ln[1:].strip()
                if added_line:
                    break
            content_line = added_line or removed_line
            fixes.append({
                "file": f,
                "rule": rule,
                "description": content_line,
                "status": None,
                "build_impact": None,
                "compiler_error": None,
                "cwe": None,
                "owasp": None,
                "explanation": None,
                "security_benefit": None,
                "finding_id": None,
            })

    # Overall build status: only trust it if the upstream step reported it.
    build_status = rem_report.get("build_status") if isinstance(rem_report, dict) else None

    return {
        "reports_dir": reports,
        "security_review": sr,
        "trivy": trivy,
        "sonar": sonar,
        "remediation_report": rem_report,
        "ai_patch": patch,
        "files_changed": changed,
        "git_diff_stat": stat,
        "remediation_summary_text": rem_sum,
        "llm_prompt": llm_prompt,
        "llm_response": llm_response,
        "fixes": fixes,
        "fix_count": fix_count or len(fixes),
        "build_status": build_status,
    }


def _resolve_finding_status(f: dict, ctx: dict) -> tuple[str, dict | None]:
    """Return (status, matched_fix) for a single security-review finding.

    status is one of: 'applied', 'skipped_build', 'skipped_residual'
    """
    fixes = ctx["fixes"]
    file_ = (f.get("file") or "").strip()
    rule_ = (f.get("rule_id") or "").strip()

    matched = None
    for fix in fixes:
        if fix.get("finding_id") and fix["finding_id"] == f.get("id"):
            matched = fix
            break
        if fix.get("file") == file_ and file_:
            matched = fix
            break
        if fix.get("rule") == rule_ and rule_:
            matched = fix
            break
        if fix.get("file") == "pom.xml" and ":" in file_:
            matched = fix
            break
        if fix.get("file") == "Dockerfile" and ":" not in file_ and file_:
            matched = fix
            break

    if matched is None:
        return "skipped_residual", None

    explicit = (matched.get("status") or "").lower()
    if explicit in ("skipped_build", "skipped-due-to-breaking", "skipped_due_to_build_failure"):
        return "skipped_build", matched
    if explicit in ("skipped_residual", "skipped-see-residual-risks"):
        return "skipped_residual", matched
    # Default: if it's in the fixes list at all (and no explicit "skipped"
    # status was recorded), treat it as applied.
    return "applied", matched


# --------------------------------------------------------------------- #
# Section 1 — Remediation Summary
# --------------------------------------------------------------------- #


def section_summary(ctx: dict) -> str:
    sr = ctx["security_review"] or {}
    findings = sr.get("findings", []) or []
    sev_counts = Counter((f.get("severity") or "INFO").upper() for f in findings)

    applied = skipped_build = skipped_residual = 0
    for f in findings:
        status, _ = _resolve_finding_status(f, ctx)
        if status == "applied":
            applied += 1
        elif status == "skipped_build":
            skipped_build += 1
        else:
            skipped_residual += 1

    build_status = ctx["build_status"]
    if build_status:
        build_line = f"Build verified: {build_status}"
    else:
        build_line = ("Build verified: _not available in this run_ — this "
                       "report is generated by a non-compiling aggregator; "
                       "see `rebuild-and-retest` job output for the actual "
                       "post-fix build result.")

    risk = sr.get("risk_score", "N/A")
    prio = sr.get("overall_priority", "N/A")

    out = [
        "# Remediation Summary",
        "",
        f"_Generated at {_now_iso()}._",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Total findings | **{len(findings)}** |",
        f"| Applied | **{applied}** |",
        f"| Skipped — due to this breaking | **{skipped_build}** |",
        f"| Skipped — see Residual Risks | **{skipped_residual}** |",
        f"| Severity breakdown | {sev_counts.get('CRITICAL', 0)} CRITICAL · "
        f"{sev_counts.get('HIGH', 0)} HIGH · {sev_counts.get('MEDIUM', 0)} MEDIUM · "
        f"{sev_counts.get('LOW', 0)} LOW · {sev_counts.get('INFO', 0)} INFO |",
        f"| Overall risk score | {risk} / 100 |",
        f"| Overall priority | {prio} |",
        "",
        build_line,
        "",
        "All changes are in the working tree; review with `git diff` before committing.",
        "",
    ]
    return "\n".join(out)


# --------------------------------------------------------------------- #
# Section 2 — Changes Made
# --------------------------------------------------------------------- #


def section_changes_made(ctx: dict) -> str:
    sr = ctx["security_review"] or {}
    findings = sr.get("findings", []) or []
    out = ["# Changes Made", ""]

    applied_lines = []
    for f in sorted(findings, key=_finding_sort_key):
        status, matched = _resolve_finding_status(f, ctx)
        if status != "applied":
            continue
        fid = f.get("id", "?")
        file_ = matched.get("file") if matched else (f.get("file") or "?")
        desc = matched.get("explanation") or matched.get("description") if matched else ""
        desc = _truncate(desc, 140) if desc else f.get("title", "")
        applied_lines.append(f"- **{fid}** — `{file_}`: {desc}")

    if not applied_lines:
        out.append("_None — no findings were applied in this run._")
    else:
        out.extend(applied_lines)
    out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------- #
# Section 3 — Changes That Remained — Due To Build Breakage
# --------------------------------------------------------------------- #


def section_changes_remained(ctx: dict) -> str:
    sr = ctx["security_review"] or {}
    findings = sr.get("findings", []) or []
    out = ["# Changes That Remained — Due To Build Breakage", ""]

    lines = []
    for f in sorted(findings, key=_finding_sort_key):
        status, matched = _resolve_finding_status(f, ctx)
        if status != "skipped_build":
            continue
        fid = f.get("id", "?")
        err = matched.get("compiler_error") if matched else None
        unblock = matched.get("explanation") if matched else None
        lines.append(f"- **{fid}** — compiler error: {_na(err)}")
        if unblock:
            lines.append(f"  - Unblock action: {_truncate(unblock, 200)}")

    if not lines:
        out.append("None.")
        out.append("")
        out.append("_(This pipeline's aggregator only reports this section when the "
                    "upstream remediation step records per-fix build-verification "
                    "data in `remediation-report.json`. If none was recorded, this "
                    "section is empty by default rather than guessed.)_")
    else:
        out.extend(lines)
    out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------- #
# Section 4 — Files Referenced
# --------------------------------------------------------------------- #


def section_files_referenced(ctx: dict) -> str:
    changed = ctx["files_changed"]
    fixes = ctx["fixes"]
    out = ["# Files Referenced", ""]
    if not changed:
        out.append("_None — no files were modified in this run._")
        out.append("")
        return "\n".join(out)

    by_file = {fx.get("file"): fx for fx in fixes}
    for f in changed:
        fx = by_file.get(f)
        reason = ""
        if fx:
            reason = fx.get("explanation") or fx.get("description") or fx.get("rule") or ""
        out.append(f"- `{f}` — {_truncate(reason, 140) if reason else '_no reason recorded_'}")
    out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------- #
# Section 5 — Vulnerability Remediations
# --------------------------------------------------------------------- #


STATUS_LABEL = {
    "applied": "Applied",
    "skipped_build": "Skipped — due to this breaking",
    "skipped_residual": "Skipped — see Residual Risks",
}


def section_vulnerability_remediations(ctx: dict) -> str:
    sr = ctx["security_review"] or {}
    findings = sr.get("findings", []) or []
    patch = ctx["ai_patch"]
    out = ["# Vulnerability Remediations", ""]

    if not findings:
        out.append("_No findings in the security review._")
        out.append("")
        return "\n".join(out)

    for f in sorted(findings, key=_finding_sort_key):
        status, matched = _resolve_finding_status(f, ctx)
        fid = f.get("id", "?")
        title = f.get("title", "Untitled finding")
        sev = (f.get("severity") or "INFO").upper()
        cwe = (matched.get("cwe") if matched else None) or f.get("cwe") or f.get("owasp")

        file_ = matched.get("file") if matched else (f.get("file") or "")
        hunk = _diff_hunk_for_file(patch, file_) if file_ else ""
        before, after = _split_hunk_before_after(hunk) if hunk else ("", "")
        lang = _lang_for_file(file_)

        build_impact = matched.get("build_impact") if matched else None
        if not build_impact:
            if status == "applied":
                build_impact = "not tracked in this run (no build-verification artefact)"
            elif status == "skipped_build":
                build_impact = "this edit broke the build; see compiler error above"
            else:
                build_impact = "skipped without edit; no build impact"

        out.append(f"### {fid} — {title}")
        out.append("")
        out.append(f"- **Severity:** {sev}")
        out.append(f"- **CWE / OWASP:** {_na(cwe, 'N/A')}")
        out.append(f"- **Status:** {STATUS_LABEL[status]}")
        out.append(f"- **File Modified:** {f'`{file_}`' if status == 'applied' and file_ else '(none)'}")
        out.append(f"- **Build Impact:** {build_impact}")
        out.append("")

        out.append("**1. Original Vulnerable Code**")
        out.append("")
        out.append(f"```{lang}")
        out.append(before if before else "_(no diff hunk captured for this file — see security-review.json for the reported location)_")
        out.append("```")
        out.append("")

        out.append("**2. Secure Replacement Code**")
        out.append("")
        out.append(f"```{lang}")
        out.append(after if after else "_(not applied — see Status above)_")
        out.append("```")
        out.append("")

        out.append("**3. Explanation of Change**")
        out.append("")
        explanation = (matched.get("explanation") if matched else None) or f.get("summary") or f.get("suggested_fix") or "_no explanation recorded_"
        out.append(_truncate(explanation, 500))
        if status == "skipped_build":
            err = matched.get("compiler_error") if matched else None
            out.append("")
            out.append(f"Compiler error: {_na(err)}")
        out.append("")

        out.append("**4. Security Benefit**")
        out.append("")
        benefit = (matched.get("security_benefit") if matched else None) or f.get("impact") or "_not recorded_"
        out.append(_truncate(benefit, 300))
        out.append("")

    return "\n".join(out)


# --------------------------------------------------------------------- #
# Section 6 — Security Improvements
# --------------------------------------------------------------------- #


def section_security_improvements(ctx: dict) -> str:
    fixes = ctx["fixes"]
    out = ["# Security Improvements", ""]
    applied = [fx for fx in fixes if (fx.get("status") or "applied").lower() == "applied" or fx.get("status") is None]
    if not applied:
        out.append("_None recorded for this run._")
        out.append("")
        return "\n".join(out)

    rules_seen = {}
    for fx in applied:
        rule = fx.get("rule") or "code-change"
        rules_seen.setdefault(rule, []).append(fx.get("file", "?"))

    for rule, files in rules_seen.items():
        files_list = ", ".join(f"`{x}`" for x in sorted(set(files)))
        out.append(f"- **{rule}** applied across: {files_list}")
    out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------- #
# Section 7 — Residual Risks
# --------------------------------------------------------------------- #


def section_residual_risks(ctx: dict) -> str:
    sr = ctx["security_review"] or {}
    findings = sr.get("findings", []) or []
    out = ["# Residual Risks", ""]

    lines = []
    for f in sorted(findings, key=_finding_sort_key):
        status, matched = _resolve_finding_status(f, ctx)
        if status != "skipped_residual":
            continue
        fid = f.get("id", "?")
        reason = (matched.get("explanation") if matched else None) or f.get("suggested_fix") or "no upstream fix / out of scope for automated remediation"
        lines.append(f"- **{fid}** ({(f.get('severity') or 'INFO').upper()}): {_truncate(reason, 200)}")

    if not lines:
        out.append("_None — every finding was either applied or is tracked under "
                    "\"Changes That Remained — Due To Build Breakage\"._")
    else:
        out.extend(lines)
    out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------- #
# Section 8 — Secure Coding Recommendations
# --------------------------------------------------------------------- #


def section_secure_coding_recommendations(ctx: dict) -> str:
    out = ["# Secure Coding Recommendations", "",
           "- Add `dependency-check-maven` (or keep Trivy/SonarCloud gates) "
           "in CI with a CVSS threshold around 7, so new CVEs fail the build "
           "before merge.",
           "- Require code review sign-off on any `# Vulnerability "
           "Remediations` entry marked Applied before it reaches `main`.",
           "- For any finding under **Residual Risks** involving secrets, "
           "route the actual values through a real secret manager "
           "(Vault / AWS Secrets Manager / Spring Cloud Config) rather than "
           "committing placeholders.",
           "- For any finding under **Residual Risks** involving password "
           "hashing, plan a migration/forced-reset flow before rollout — "
           "changing the encoder invalidates existing credentials.",
           "- Re-run this report after every remediation run so the "
           "Applied/Skipped counts stay current with the working tree.",
           ""]
    return "\n".join(out)


# --------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------- #


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    ap.add_argument("--out", type=Path, default=Path("reports/remediation-report.md"))
    args = ap.parse_args()

    if not args.reports.exists():
        print(f"ERROR: reports dir {args.reports} does not exist", file=sys.stderr)
        return 1

    ctx = _load_ctx(args.reports)

    parts: list[str] = [
        "# Secure Remediation Report",
        "",
        f"_Generated by `scripts/generate-remediation-report.py` at {_now_iso()}._  ",
        f"_All inputs are read from `{args.reports}/`. This is a non-editing, "
        f"non-compiling aggregator — it does not touch source code or the LLM; "
        f"it only formats artefacts already produced earlier in the pipeline._",
        "",
        "---",
        "",
        section_summary(ctx),
        section_changes_made(ctx),
        section_changes_remained(ctx),
        section_files_referenced(ctx),
        section_vulnerability_remediations(ctx),
        section_security_improvements(ctx),
        section_residual_risks(ctx),
        section_secure_coding_recommendations(ctx),
        "---",
        "",
        "_End of report._",
        "",
    ]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(parts), encoding="utf-8")
    print(f"Remediation report written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
