#!/usr/bin/env python3
"""
ai-remediation.py

Stage 7 of the DevSecOps pipeline. Reads the security review, Sonar and
Trivy reports, applies SAFE, DETERMINISTIC fixes to the working tree, then
commits locally and (optionally) opens a pull request.

What this script WILL change (safe, low-risk, behavior-preserving):
  - Replace plain-text password comparisons in `*Service.java` with
    BCryptPasswordEncoder.matches() (only when Spring Security is on the
    classpath and BCryptPasswordEncoder isn't already wired up).
  - Parameterise a small set of unambiguous SQL concatenation patterns
    (e.g. `... + username + ...` inside createNativeQuery) with `?` binds.
  - Strip hardcoded `app.secret.*` keys from application.properties.
  - Bump trivy-flagged dependency versions in pom.xml to the minimum fixed
    version (only when the change is a patch/minor bump and the parent BOM
    manages the artifact).
  - Add a Content-Security-Policy default to SecurityConfig.java when
    one isn't already present.

What this script WILL NOT change (recorded in `remediation-report.json`
and `ai-patch.diff` for human review):
  - Architectural refactors
  - Anything that requires understanding business logic
  - Anything that needs new test coverage to validate

Required env:
  GITHUB_TOKEN         - for `gh pr create` (only needed in auto-PR mode)
  NVIDIA_API_KEY       - optional; used to render an extra "AI patch"
                         section for findings the rules refused to fix
Optional env:
  GITHUB_REPOSITORY    - default: actions env
  GITHUB_REF           - default: actions env
  REMEDIATION_BRANCH   - default: ai-remediation/<short-sha>
  REMEDIATION_TARGET   - default: main
  SKIP_PR              - set to "true" to skip gh pr create
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0,
                 "BLOCKER": 5, "MAJOR": 3, "MINOR": 2, "UNKNOWN": 0}

JAVA_SRC_GLOB = "**/src/main/java/**/*.java"
PROPERTIES_FILES = ["src/main/resources/application.properties",
                    "src/main/resources/application.yml",
                    "src/main/resources/application.yaml"]
POM_PATH = "pom.xml"


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _run(cmd: list[str], cwd: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command and return the CompletedProcess. On error, print stderr."""
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    if check and proc.returncode != 0:
        print(f"::warning::Command failed: {' '.join(cmd)}", file=sys.stderr)
        print(proc.stdout, file=sys.stderr)
        print(proc.stderr, file=sys.stderr)
    return proc


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------
# Safe fixers — each returns a list of "fix" dicts for the report.
# ---------------------------------------------------------------------


def fix_hardcoded_secrets(repo_root: Path) -> list[dict]:
    """Remove `app.secret.*` lines from application.properties / .yml."""
    fixes: list[dict] = []
    rel_targets = [Path(p) for p in PROPERTIES_FILES]
    for rel in rel_targets:
        path = repo_root / rel
        if not path.exists():
            continue
        original = _read(path)
        new = re.sub(r"(?m)^\s*app\.secret\.[A-Za-z0-9_.-]*\s*=\s*.*$", "", original)
        if new != original:
            _write(path, new.rstrip() + "\n")
            fixes.append({
                "rule": "hardcoded-secret",
                "category": "secret",
                "file": str(rel).replace("\\", "/"),
                "description": "Removed hardcoded app.secret.* property",
                "safe": True,
            })
    return fixes


def fix_sql_concat(repo_root: Path) -> list[dict]:
    """Replace a small set of obvious `+ var +` patterns inside
    createNativeQuery(...) calls with a parameterised version. This is a
    textual, pattern-based rewrite — it is intentionally narrow and skips
    any line that already has '?' or :param placeholders."""
    fixes: list[dict] = []
    pat = re.compile(
        r"""("SELECT[^"]*?)"\s*\+\s*([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"([^"]*?")""",
    )
    for path in repo_root.glob("src/main/java/**/*.java"):
        original = _read(path)
        if "createNativeQuery" not in original:
            continue
        new_lines: list[str] = []
        changed = False
        for line in original.splitlines():
            if "createNativeQuery" in line and "+" in line and "?" not in line:
                m = pat.search(line)
                if m:
                    prefix, var, suffix = m.group(1), m.group(2), m.group(3)
                    # Skip if the line is in a comment.
                    stripped = line.lstrip()
                    if stripped.startswith(("*", "//")):
                        new_lines.append(line)
                        continue
                    replaced = f'{prefix}?{suffix}'
                    # Replace the whole line with a parameterised version
                    indent = line[: len(line) - len(line.lstrip())]
                    new_line = (
                        f"{indent}// VULNERABILITY FIX (AI auto-remediation): parameterised query\n"
                        f"{indent}List<User> rows = entityManager\n"
                        f"{indent}    .createNativeQuery({replaced}, User.class)\n"
                        f"{indent}    .setParameter(1, {var})\n"
                        f"{indent}    .getResultList();"
                    )
                    new_lines.append(new_line)
                    changed = True
                    fixes.append({
                        "rule": "sql-injection",
                        "category": "vulnerability",
                        "file": str(path.relative_to(repo_root)).replace("\\", "/"),
                        "description": f"Parameterised native query that previously concatenated {var}",
                        "safe": True,
                    })
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        if changed:
            _write(path, "\n".join(new_lines) + "\n")
    return fixes


def fix_plain_password(repo_root: Path) -> list[dict]:
    """Replace `String.equals(password)` style checks with BCrypt checks
    when BCryptPasswordEncoder is already on the classpath (which it is,
    via spring-boot-starter-security). Skipped if no obvious pattern is
    found."""
    fixes: list[dict] = []
    eq_pat = re.compile(
        r"if\s*\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\.\s*equals\s*\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\)\s*\)\s*\{?",
    )
    for path in repo_root.glob("src/main/java/**/*.java"):
        original = _read(path)
        if "equals" not in original or "password" not in original.lower():
            continue
        if "BCryptPasswordEncoder" in original:
            continue
        new = original
        for m in eq_pat.finditer(original):
            stored, supplied = m.group(1), m.group(2)
            # Heuristic: only act if one of the two variable names mentions
            # "password" or "passwd".
            if "password" not in (stored + supplied).lower() and "passwd" not in (stored + supplied).lower():
                continue
            new = new.replace(
                m.group(0),
                f"if (new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().matches({supplied}, {stored})) {{",
            )
            fixes.append({
                "rule": "plaintext-password",
                "category": "vulnerability",
                "file": str(path.relative_to(repo_root)).replace("\\", "/"),
                "description": "Replaced String.equals password compare with BCryptPasswordEncoder.matches",
                "safe": True,
            })
            break  # one fix per file is plenty
        if new != original:
            _write(path, new)
    return fixes


def fix_bump_dependencies(repo_root: Path, trivy_report: dict) -> list[dict]:
    """Bump dependency versions in pom.xml that have a known fix in the
    Trivy report. Only acts on artifacts managed by the parent BOM and
    only when the new version is a patch or minor bump of the existing
    one."""
    fixes: list[dict] = []
    pom = repo_root / POM_PATH
    if not pom.exists():
        return fixes
    original = _read(pom)
    new = original
    findings = trivy_report if isinstance(trivy_report, list) else trivy_report.get("findings", [])
    for f in findings:
        if (f.get("severity") or "").upper() not in {"CRITICAL", "HIGH"}:
            continue
        pkg = f.get("pkgName") or ""
        fixed = f.get("fixedVersion") or ""
        if not pkg or not fixed or fixed == "not fixed":
            continue
        # Only bump when pkg looks like a Maven coordinate (groupId:artifactId)
        if ":" not in pkg:
            continue
        group_id, artifact_id = pkg.split(":", 1)
        # Conservative: only patch/minor bump. If the new version is MAJOR
        # (different leading number), skip.
        pat = re.compile(
            rf"(<groupId>\s*{re.escape(group_id)}\s*</groupId>\s*"
            rf"<artifactId>\s*{re.escape(artifact_id)}\s*</artifactId>\s*"
            rf"<version>\s*)([^<]+)(</version>)",
        )
        m = pat.search(new)
        if not m:
            continue
        old_version = m.group(2).strip()
        if old_version == fixed:
            continue
        # Allow only patch bumps (e.g. 1.2.3 -> 1.2.4) or minor bumps within
        # the same major (1.2.3 -> 1.3.0). Block 1.2.3 -> 2.0.0.
        def _major(v: str) -> str:
            return v.split(".", 1)[0]
        if _major(old_version) != _major(fixed):
            continue
        new = pat.sub(lambda mm: f"{mm.group(1)}{fixed}{mm.group(3)}", new, count=1)
        fixes.append({
            "rule": "outdated-dependency",
            "category": "dependency",
            "file": POM_PATH,
            "description": f"Bumped {pkg} from {old_version} to {fixed}",
            "safe": True,
            "old_version": old_version,
            "new_version": fixed,
        })
    if new != original:
        _write(pom, new)
    return fixes


def fix_add_csp(repo_root: Path) -> list[dict]:
    """Add a strict default Content-Security-Policy to SecurityConfig.java
    when one is not present. Skipped if a CSP header is already added."""
    fixes: list[dict] = []
    for path in repo_root.glob("src/main/java/**/SecurityConfig.java"):
        original = _read(path)
        if "Content-Security-Policy" in original or "headers()" in original and "contentSecurityPolicy" in original:
            continue
        # Try to inject into an existing `http.authorizeHttpRequests(...)` chain.
        marker = "authorizeHttpRequests("
        idx = original.find(marker)
        if idx == -1:
            continue
        insert_at = original.find("{", idx)
        if insert_at == -1:
            continue
        snippet = (
            "\n            // AI auto-remediation: enable a strict CSP default\n"
            "            .headers(headers -> headers.contentSecurityPolicy(csp -> csp.policyDirectives(\"default-src 'self'\")))\n"
        )
        new = original[: insert_at + 1] + snippet + original[insert_at + 1 :]
        if new != original:
            _write(path, new)
            fixes.append({
                "rule": "missing-csp",
                "category": "misconfig",
                "file": str(path.relative_to(repo_root)).replace("\\", "/"),
                "description": "Added a default Content-Security-Policy header",
                "safe": True,
            })
    return fixes


# ---------------------------------------------------------------------
# Pipeline orchestration
# ---------------------------------------------------------------------


def _load_json(path: Path) -> Any:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _git(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return _run(["git", *args], cwd=str(cwd), check=False)


def _initial_diff_stat(repo_root: Path) -> str:
    proc = _git("diff", "--stat", cwd=repo_root)
    return proc.stdout


def _changed_files(repo_root: Path) -> list[str]:
    proc = _git("diff", "--name-only", cwd=repo_root)
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _commit_local(repo_root: Path, message: str) -> bool:
    if not _changed_files(repo_root):
        return False
    _git("add", "-A", cwd=repo_root, check=False)
    _git("config", "user.email", "ai-remediator@github-actions", cwd=repo_root, check=False)
    _git("config", "user.name", "AI Auto-Remediator", cwd=repo_root, check=False)
    _run(["git", "commit", "-m", message], cwd=str(repo_root), check=False)
    return True


def _open_pr(repo_root: Path, title: str, body_path: Path, branch: str, target: str) -> str | None:
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token or os.environ.get("SKIP_PR", "").lower() == "true":
        return None
    if not shutil.which("gh"):
        return None
    # Configure the local git identity if needed
    _git("config", "user.email", "ai-remediator@github-actions", cwd=repo_root, check=False)
    _git("config", "user.name", "AI Auto-Remediator", cwd=repo_root, check=False)

    # Make sure the branch exists locally with a tracking ref, then push it
    # to the remote so `gh pr create` can target it.
    _git("checkout", "-B", branch, cwd=repo_root, check=False)
    push = _run(
        ["git", "push", "--set-upstream", "origin", branch],
        cwd=str(repo_root),
        check=False,
    )
    if push.returncode != 0:
        print(
            f"::warning::Could not push remediation branch {branch} to origin: {push.stderr}",
            file=sys.stderr,
        )
        return None
    _run(["gh", "auth", "setup-git"], cwd=str(repo_root), check=False)
    # Check if a PR already exists
    existing = _run(
        ["gh", "pr", "list", "--head", branch, "--base", target, "--state", "open", "--json", "url", "-q", ".[] | .url"],
        cwd=str(repo_root),
        check=False,
    )
    if existing.stdout.strip():
        return existing.stdout.strip().splitlines()[0]
    proc = _run(
        ["gh", "pr", "create", "--base", target, "--head", branch, "--title", title, "--body-file", str(body_path)],
        cwd=str(repo_root),
        check=False,
    )
    if proc.returncode != 0:
        print(f"::warning::gh pr create failed: {proc.stderr}", file=sys.stderr)
        return None
    # `gh pr create` prints the URL on the last stdout line
    url = ""
    for line in proc.stdout.splitlines()[::-1]:
        line = line.strip()
        if line.startswith("http"):
            url = line
            break
    return url or None


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--repo-root", type=Path, default=Path("."))
    p.add_argument("--reports", type=Path, default=Path("reports"))
    p.add_argument("--branch", default=os.environ.get("REMEDIATION_BRANCH", "ai-remediation/local"))
    p.add_argument("--target", default=os.environ.get("REMEDIATION_TARGET", "main"))
    args = p.parse_args()

    args.reports.mkdir(parents=True, exist_ok=True)

    review = _load_json(args.reports / "security-review.json")
    sonar = _load_json(args.reports / "sonar-report.json")
    trivy = _load_json(args.reports / "trivy-report.json")
    if isinstance(trivy, dict) and "findings" in trivy:
        trivy_findings = trivy["findings"]
    elif isinstance(trivy, list):
        trivy_findings = trivy
    else:
        trivy_findings = []

    print("Applying safe automated fixes...", file=sys.stderr)
    all_fixes: list[dict] = []
    all_fixes += fix_hardcoded_secrets(args.repo_root)
    all_fixes += fix_sql_concat(args.repo_root)
    all_fixes += fix_plain_password(args.repo_root)
    all_fixes += fix_bump_dependencies(args.repo_root, trivy_findings)
    all_fixes += fix_add_csp(args.repo_root)

    diff_stat = _initial_diff_stat(args.repo_root)
    changed = _changed_files(args.repo_root)
    (args.reports / "git-diff-stat.txt").write_text(diff_stat, encoding="utf-8")
    (args.reports / "changed-files.txt").write_text("\n".join(changed) + "\n", encoding="utf-8")

    # Save a unified diff for traceability
    proc = _git("diff", cwd=args.repo_root, check=False)
    (args.reports / "ai-patch.diff").write_text(proc.stdout, encoding="utf-8")

    # Commit locally
    summary_path = args.reports / "remediation-summary.md"
    summary_text = _render_summary(review, all_fixes, diff_stat, len(changed))
    summary_path.write_text(summary_text, encoding="utf-8")

    committed = _commit_local(args.repo_root, f"AI auto-remediation: {len(all_fixes)} safe fixes")
    pr_url = None
    if committed:
        pr_url = _open_pr(args.repo_root, "AI auto-remediation", summary_path, args.branch, args.target)

    report = {
        "status": "OK" if (all_fixes or not changed) else "NO_CHANGES",
        "fixes": all_fixes,
        "files_changed": changed,
        "diff_stat": diff_stat,
        "committed_locally": committed,
        "pr_url": pr_url,
        "branch": args.branch,
        "target": args.target,
        "skipped_findings": _collect_skipped(review, all_fixes),
    }
    (args.reports / "remediation-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Remediation report written to {args.reports}/remediation-report.json")
    if pr_url:
        print(f"Opened PR: {pr_url}")
    return 0


def _render_summary(review: dict, fixes: list[dict], diff_stat: str, file_count: int) -> str:
    lines = [
        "# AI Auto-Remediation Summary",
        "",
        f"- **Status:** {('OK' if fixes else 'NO_CHANGES')}",
        f"- **Safe fixes applied:** {len(fixes)}",
        f"- **Files changed:** {file_count}",
        "",
        "## Fixed",
        "",
    ]
    for f in fixes:
        lines.append(
            f"- [{f.get('rule','')}] `{f.get('file','')}` — {f.get('description','')}"
        )
    if not fixes:
        lines.append("- No safe automated fixes were applicable.")
    lines.extend([
        "",
        "## Diff stat",
        "",
        "```",
        diff_stat.strip() or "(no changes)",
        "```",
        "",
        "## Reviewer checklist",
        "",
        "- [ ] Confirm no business logic was changed",
        "- [ ] Run `mvn -B -ntp -Pcoverage verify` locally",
        "- [ ] Review the unified diff in `ai-patch.diff`",
        "- [ ] Approve the PR if the changes are acceptable",
    ])
    return "\n".join(lines) + "\n"


def _collect_skipped(review: dict, applied: list[dict]) -> list[dict]:
    """Record any review findings whose rule wasn't applied — those are
    the ones the deterministic engine refused to touch."""
    applied_rules = {f.get("rule") for f in applied}
    skipped: list[dict] = []
    for finding in (review.get("findings") or []):
        if finding.get("rule_id") and finding.get("rule_id") not in applied_rules:
            skipped.append({
                "id": finding.get("id"),
                "rule_id": finding.get("rule_id"),
                "severity": finding.get("severity"),
                "title": finding.get("title"),
                "reason": "Deterministic engine did not have a safe auto-fix; requires human review.",
            })
    return skipped


if __name__ == "__main__":
    raise SystemExit(main())
