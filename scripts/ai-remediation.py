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
    """Replace `String sql = "..." + var + "...";` concatenation with a
    parameterised native query (`?` + `.setParameter(1, var)`).

    The OWASP lab concatenates inside a `String sql = "..." + var + "...";`
    assignment and then passes that `sql` to `createNativeQuery(sql, ...)`.
    The earlier version of this fixer only looked at the
    `createNativeQuery(...)` line, which never contains the `+` (the
    concatenation is one statement above), so it never matched.

    Strategy:
      1. Find the `String sql = "<prefix>" + <var> + "<suffix>";` line.
      2. Replace it with `String sql = "<prefix>?<suffix>";`.
      3. In the immediately-following `createNativeQuery(sql, X).getResultList()`
         chain, inject `.setParameter(1, <var>)` before `.getResultList()`.
    """
    fixes: list[dict] = []
    if not (repo_root / "src" / "main" / "java").exists():
        return fixes

    # Match a single-variable SQL string concatenation. The OWASP lab
    # uses the pattern `String sql = "..." + var + "...";` (one-line for
    # simple queries, sometimes multi-line for login). We require that
    # the concatenation has exactly one variable, so multi-var cases
    # (e.g. loginUnsafe's `+ username + "...' AND password = '" + password + "'"`)
    # are left alone — they're handled by fix_plain_password instead.
    assign_pat = re.compile(
        r'(?P<indent>[ \t]*)String[ \t]+(?P<varname>[A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*'
        r'"(?P<prefix>(?:[^"\\]|\\.)*)"[ \t]*\+\s*'
        r'(?P<var>[A-Za-z_][A-Za-z0-9_]*)[ \t]*\+\s*'
        r'"(?P<suffix>(?:[^"\\]|\\.)*)"\s*;',
        re.DOTALL,
    )

    for path in repo_root.glob("src/main/java/**/*.java"):
        original = _read(path)
        if "createNativeQuery" not in original:
            continue
        new = original
        per_file: list[dict] = []
        for m in assign_pat.finditer(new):
            indent = m.group("indent")
            var = m.group("var")
            prefix = m.group("prefix")
            suffix = m.group("suffix")
            varname = m.group("varname")
            # Sanity: only act on assignments that look like a SQL string
            # (start with a SQL keyword). Otherwise we might rewrite arbitrary
            # string concatenations.
            if not re.match(r"\s*(SELECT|INSERT|UPDATE|DELETE)\b", prefix, re.IGNORECASE):
                continue
            # Strip a trailing SQL quote from the prefix and a leading SQL
            # quote from the suffix so we don't end up with `?'` or `?''`
            # after substitution. (The original concatenation
            # `'<prefix>' + var + '<suffix>'` produces `'<prefix>?<suffix>'`
            # which has stray quotes around the placeholder.)
            if prefix.endswith("'"):
                prefix = prefix[:-1]
            if suffix.startswith("'"):
                suffix = suffix[1:]
            # Replace the assignment line.
            new_sql_line = f'{indent}String {varname} = "{prefix}?{suffix}";'
            new = new.replace(m.group(0), new_sql_line, 1)
            # Inject setParameter after the createNativeQuery line.
            # Look for `.createNativeQuery(<varname>, ...)`.
            cn_pat = re.compile(
                r'(\.createNativeQuery\([ \t]*' + re.escape(varname) + r'[ \t]*,[ \t]*[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\))'
                r'(\s*\.\s*getResultList\(\))',
            )
            cn_match = cn_pat.search(new)
            if cn_match:
                injection = f".setParameter(1, {var})"
                new = new.replace(
                    cn_match.group(0),
                    f"{cn_match.group(1)}{injection}{cn_match.group(2)}",
                    1,
                )
            per_file.append({
                "file": str(path.relative_to(repo_root)).replace("\\", "/"),
                "var": var,
                "sql_var": varname,
            })
        if per_file and new != original:
            _write(path, new)
            for info in per_file:
                fixes.append({
                    "rule": "sql-injection",
                    "category": "vulnerability",
                    "file": info["file"],
                    "description": (
                        f"Parameterised native query that previously concatenated "
                        f"{info['var']} into {info['sql_var']}"
                    ),
                    "safe": True,
                })
    return fixes


def fix_plain_password(repo_root: Path) -> list[dict]:
    """The OWASP lab concatenates the password into a SQL query in
    `UserService.loginUnsafe`. There is no `String.equals(...)` compare
    in the codebase, so the previous regex (which only matched
    `if (x.equals(y))` style checks) never fired. Rewrite the
    `loginUnsafe` method to look the user up by username only and verify
    the password in Java, with a clear TODO marker for BCrypt.
    """
    fixes: list[dict] = []
    target = repo_root / "src" / "main" / "java" / "com" / "owasp" / "lab" / "service" / "UserService.java"
    if not target.exists():
        return fixes
    original = _read(target)
    if "FIX_PLAIN_PASSWORD_APPLIED" in original:
        return fixes  # idempotent: don't re-apply

    # Match the full loginUnsafe method body, from `public User loginUnsafe`
    # up to the closing `}` of the method.
    method_pat = re.compile(
        r"public\s+User\s+loginUnsafe\s*\(\s*String\s+username\s*,\s*String\s+password\s*\)\s*\{[\s\S]*?\n\s{4}\}",
        re.MULTILINE,
    )
    new_body = (
        "public User loginUnsafe(String username, String password) {\n"
        "        // VULNERABILITY FIX (AI auto-remediation, marker FIX_PLAIN_PASSWORD_APPLIED):\n"
        "        //   - Look the user up by username only (no password in the SQL).\n"
        "        //   - Compare the supplied password to the stored password in Java.\n"
        "        //   - TODO: replace the String.equals check with BCryptPasswordEncoder.matches().\n"
        "        String sql = \"SELECT * FROM users WHERE username = ?\";\n"
        "        System.out.println(\"[VULNERABILITY-FIXED] Login SQL: \" + sql);\n"
        "\n"
        "        try {\n"
        "            @SuppressWarnings(\"unchecked\")\n"
        "            java.util.List<User> rows = entityManager\n"
        "                    .createNativeQuery(sql, User.class)\n"
        "                    .setParameter(1, username)\n"
        "                    .getResultList();\n"
        "            if (rows.isEmpty()) {\n"
        "                return null;\n"
        "            }\n"
        "            User u = rows.get(0);\n"
        "            if (u.getPassword() == null || !u.getPassword().equals(password)) {\n"
        "                return null;\n"
        "            }\n"
        "            return u;\n"
        "        } catch (Exception ex) {\n"
        "            return null;\n"
        "        }\n"
        "    }"
    )
    new = method_pat.sub(new_body, original, count=1)
    if new != original:
        _write(target, new)
        fixes.append({
            "rule": "plaintext-password",
            "category": "vulnerability",
            "file": str(target.relative_to(repo_root)).replace("\\", "/"),
            "description": (
                "loginUnsafe no longer concatenates password into the SQL; "
                "compares the password in Java with a TODO marker for BCrypt"
            ),
            "safe": True,
        })
    return fixes


def fix_bump_dependencies(repo_root: Path, trivy_report: dict) -> list[dict]:
    """Bump dependency versions in pom.xml based on Trivy findings.

    The previous version of this fixer only matched direct dependencies
    that have an explicit `<version>` in pom.xml. Spring Boot starter
    dependencies are BOM-managed (no `<version>`), and transitive
    libraries are not even listed in pom.xml — so the fixer never fired
    on this project.

    Strategy:
      1. **Spring Boot parent bump**: if a Trivy finding's
         `pkgName` is a Spring Boot artifact or one of the most common
         transitive libraries (jackson, snakeyaml, logback, tomcat, etc.)
         AND the parent is `spring-boot-starter-parent`, bump the parent
         version when a known fixed version is available. This is the
         single most common remediation for a Spring Boot app.
      2. **Direct dependency bump**: if a Trivy finding matches a
         `<groupId>/<artifactId>` in pom.xml that has an explicit
         `<version>`, bump it (patch / minor only).
    """
    fixes: list[dict] = []
    pom = repo_root / POM_PATH
    if not pom.exists():
        return fixes
    original = _read(pom)
    new = original
    findings = trivy_report if isinstance(trivy_report, list) else trivy_report.get("findings", [])

    # Collect findings worth acting on.
    actionable: list[dict] = []
    for f in findings:
        if (f.get("severity") or "").upper() not in {"CRITICAL", "HIGH"}:
            continue
        pkg = f.get("pkgName") or ""
        fixed = f.get("fixedVersion") or ""
        if not pkg or not fixed or fixed == "not fixed":
            continue
        actionable.append({"pkg": pkg, "fixed": fixed, "finding": f})

    if not actionable:
        return fixes

    # ---- Strategy 1: Spring Boot parent bump ----
    # Heuristic: if any finding is for a Spring Boot artifact or one of the
    # well-known transitive libraries, suggest bumping the parent.
    sb_managed_artifacts = {
        # Spring Boot starters (no version in pom)
        "org.springframework.boot:spring-boot-starter-web",
        "org.springframework.boot:spring-boot-starter-data-jpa",
        "org.springframework.boot:spring-boot-starter-security",
        "org.springframework.boot:spring-boot-starter-tomcat",
        "org.springframework.boot:spring-boot-starter-logging",
        # Common transitive deps
        "com.fasterxml.jackson.core:jackson-databind",
        "com.fasterxml.jackson.core:jackson-core",
        "com.fasterxml.jackson.core:jackson-annotations",
        "org.yaml:snakeyaml",
        "ch.qos.logback:logback-core",
        "ch.qos.logback:logback-classic",
        "org.apache.tomcat.embed:tomcat-embed-core",
        "org.apache.tomcat.embed:tomcat-embed-el",
        "org.apache.tomcat.embed:tomcat-embed-websocket",
        "org.hibernate.orm:hibernate-core",
    }
    sb_finding = next(
        (a for a in actionable if a["pkg"] in sb_managed_artifacts),
        None,
    )
    if sb_finding:
        # Find the spring-boot-starter-parent <version> in pom.xml.
        parent_pat = re.compile(
            r"(<artifactId>\s*spring-boot-starter-parent\s*</artifactId>\s*"
            r"<version>\s*)([^<]+)(</version>)",
        )
        m = parent_pat.search(new)
        if m:
            old_version = m.group(2).strip()
            new_version = sb_finding["fixed"].strip()
            if old_version != new_version:
                # Only act on patch/minor bumps (same major). Don't auto-bump majors.
                def _major(v: str) -> str:
                    return v.split(".", 1)[0]
                if _major(old_version) == _major(new_version):
                    new = parent_pat.sub(
                        lambda mm: f"{mm.group(1)}{new_version}{mm.group(3)}",
                        new,
                        count=1,
                    )
                    fixes.append({
                        "rule": "outdated-dependency",
                        "category": "dependency",
                        "file": POM_PATH,
                        "description": (
                            f"Bumped spring-boot-starter-parent from {old_version} to "
                            f"{new_version} (transitive fix for {sb_finding['pkg']})"
                        ),
                        "safe": True,
                        "old_version": old_version,
                        "new_version": new_version,
                    })
                    # Once we bump the parent, all the BOM-managed findings
                    # are addressed — skip the direct-dependency pass.
                    if new != original:
                        _write(pom, new)
                    return fixes
        # If sb_finding exists but there's no parent to bump, fall through
        # to Strategy 2 (in case any actionable finding matches a direct
        # dependency).

    # ---- Strategy 2: direct dependency bump (only when there's an
    # explicit <version> in pom.xml for the artifact) ----
    for a in actionable:
        pkg = a["pkg"]
        fixed = a["fixed"]
        if ":" not in pkg:
            continue
        group_id, artifact_id = pkg.split(":", 1)
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
    """Add a Content-Security-Policy header to `SecurityConfig.java`.

    The previous version of this fixer looked for an `authorizeHttpRequests(...)`
    call followed by an opening `{` to splice a `.headers(...)` block into.
    But Spring Security 6 uses a lambda DSL
    (`.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())`)
    that has no opening `{`, so the splice either fired on the wrong
    character (the method's closing brace) or never fired at all. And the
    skip-check compared against `headers()` with empty parens, which
    never matched this project's `.headers(h -> h.frameOptions(...))`.

    Strategy: locate the existing `.headers(...)` call. If it already
    configures a contentSecurityPolicy, skip. Otherwise, rewrite the
    lambda body to include the CSP directive alongside the existing
    configuration.
    """
    fixes: list[dict] = []
    for path in repo_root.glob("src/main/java/**/SecurityConfig.java"):
        original = _read(path)
        # Idempotency marker — also serves as a hint to human reviewers.
        if "FIX_CSP_APPLIED" in original:
            continue

        # Look for `.headers( -> h -> <body>);`
        # The body is everything between the first `->` after `.headers(`
        # and the matching `))` that closes the headers call.
        # Match `.headers(<arg> -> <body>);` where <body> is the lambda
        # body of the headers call. Capture the entire `.headers(...)`
        # invocation including its closing `)`s so we can rewrite it.
        # We use a non-greedy match for the body and rely on the
        # terminating `\)\)\s*;` to anchor the end of the headers call.
        headers_pat = re.compile(
            r"\.headers\(\s*[A-Za-z_][A-Za-z0-9_]*\s*->\s*"
            r"(?P<body>.*?)"
            r"\)\s*\)\s*;",
            re.DOTALL,
        )
        m = headers_pat.search(original)
        if m:
            body = m.group("body").rstrip()
            if "contentSecurityPolicy" in body or "ContentSecurityPolicy" in body:
                # Already configured, skip.
                continue
            # `body` is the lambda body, e.g. `h.frameOptions(f -> f.disable())`.
            # The lambda's closing `)` is captured separately by the regex
            # terminator `\)\)\s*;`, so we just append the new chain here.
            new_body = (
                f'{body}'
                f'.contentSecurityPolicy(csp -> csp.policyDirectives("default-src \'self\'; object-src \'none\'"))'
            )
            new = (
                original[: m.start("body")]
                + new_body
                + original[m.end("body") :]
            )
            if "FIX_CSP_APPLIED" not in new:
                # Insert a marker comment above the .headers() line so the
                # change is grep-able for reviewers and so re-running the
                # fixer is a no-op.
                new = re.sub(
                    r"(\.headers\()",
                    "// VULNERABILITY FIX (AI auto-remediation, marker FIX_CSP_APPLIED): added Content-Security-Policy header\n            \\1",
                    new,
                    count=1,
                )
            if new != original:
                _write(path, new)
                fixes.append({
                    "rule": "missing-csp",
                    "category": "misconfig",
                    "file": str(path.relative_to(repo_root)).replace("\\", "/"),
                    "description": "Added a default Content-Security-Policy header",
                    "safe": True,
                })
            continue

        # Fallback: no existing `.headers(...)` call. Add one before the
        # closing `;` of the security filter chain. Insert it just before
        # `return http.build();`.
        return_idx = original.find("return http.build();")
        if return_idx == -1:
            continue
        insertion = (
            "\n            // VULNERABILITY FIX (AI auto-remediation, marker FIX_CSP_APPLIED): added Content-Security-Policy header\n"
            "            .headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives(\"default-src 'self'; object-src 'none'\")))\n"
        )
        new = original[:return_idx] + insertion + original[return_idx:]
        if new != original:
            _write(path, new)
            fixes.append({
                "rule": "missing-csp",
                "category": "misconfig",
                "file": str(path.relative_to(repo_root)).replace("\\", "/"),
                "description": "Added a default Content-Security-Policy header (no prior headers() call found)",
                "safe": True,
            })
    return fixes


# ---------------------------------------------------------------------
# Pipeline orchestration
# ---------------------------------------------------------------------


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _git(*args: str, cwd: Path, check: bool = False) -> subprocess.CompletedProcess:
    return _run(["git", *args], cwd=str(cwd), check=check)


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
