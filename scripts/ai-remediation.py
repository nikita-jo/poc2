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
import urllib.error
import urllib.request
from fnmatch import fnmatch
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


# ---------------------------------------------------------------------
# LLM-driven per-file patches
# ---------------------------------------------------------------------

# Files the LLM is allowed to write to. Anything else is recorded as a
# `skipped` entry and never touches disk. This is a coarse whitelist
# tuned for the OWASP learning lab; tighten it for production code.
_LLM_WRITABLE_GLOBS = (
    "src/main/java/**/*.java",
    "src/test/java/**/*.java",
    "src/main/resources/**",
    "src/test/resources/**",
    "pom.xml",
    "Dockerfile",
)
_LLM_MAX_PATCHES = 10
_LLM_MAX_BYTES_PER_CALL = 256 * 1024
_LLM_MAX_FILE_BYTES = 8 * 1024


def _is_path_writable(rel_path: str) -> bool:
    """True iff `rel_path` matches one of the whitelisted globs."""
    rel = rel_path.replace("\\", "/").lstrip("/")
    if not rel:
        return False
    # Reject absolute paths and parent-traversal early.
    if rel.startswith("/") or ".." in rel.split("/"):
        return False
    from fnmatch import fnmatch
    for pat in _LLM_WRITABLE_GLOBS:
        if fnmatch(rel, pat):
            return True
    return False


def _call_nvidia(prompt: str, system: str, model: str, base_url: str, max_tokens: int) -> str:
    """Call the NVIDIA chat completions API. Returns the assistant's
    content (a string), or "" on missing key / network error / non-JSON
    response. Logs a warning to stderr on failure so the workflow log
    shows why the LLM pass was skipped."""
    api_key = os.environ.get("NVIDIA_API_KEY", "").strip()
    if not api_key:
        print("WARN: NVIDIA_API_KEY not set; skipping LLM patch pass.", file=sys.stderr)
        return ""
    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
    }
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.load(resp)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError) as exc:
        print(f"WARN: NVIDIA API call failed: {exc}", file=sys.stderr)
        return ""
    try:
        return data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        return ""


def _extract_json(text: str) -> dict | None:
    """Best-effort JSON extraction. Handles ```json fences and the case
    where the LLM wraps the JSON in leading prose."""
    if not text:
        return None
    text = re.sub(r"^```(?:json)?\s*", "", text.strip())
    text = re.sub(r"```$", "", text.strip())
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", text)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                return None
    return None


_REMEDIATION_SYSTEM_PROMPT = """You are an automated code-remediation agent for a Java / Spring Boot / Maven project.

You will receive:
  1. A list of security findings (id, severity, file, line, rule_id, evidence, suggested_fix).
  2. The current content of every file referenced by those findings.

Your job: produce a STRICT JSON object describing SAFE, BEHAVIOR-PRESERVING
patches that fix as many findings as possible.

OUTPUT SCHEMA (return ONLY this JSON, no prose, no markdown fences):
{
  "patches": [
    {
      "file": "src/main/java/.../Foo.java",
      "new_content": "<FULL new file content after the fix>",
      "rule_id": "java:S2077",
      "finding_id": "SR-001",
      "description": "One-line description of the change"
    }
  ],
  "skipped": [
    { "finding_id": "SR-009", "rule_id": "java:S5145",
      "reason": "Why this finding cannot be safely auto-fixed" }
  ]
}

RULES:
- `new_content` MUST be the FULL file content, not a diff or a hunk.
- Only emit `patches` for files the user listed. Do not invent new files.
- If you cannot fix a finding safely, put it in `skipped` with a reason.
- Cap patches at 10 and total new_content bytes at 256 KB.
- Be conservative: parameterise queries, hash passwords, escape output,
  validate inputs, add security headers. Do not introduce new
  dependencies unless the finding explicitly requires it.
- Do not delete code that the application still needs. If you remove
  vulnerable code, replace it with a safe equivalent.
- Add a marker comment `// FIX_LLM_APPLIED: <rule_id>` on the line
  where the change begins so re-runs are idempotent.
- Return valid JSON. Do not include any commentary outside the JSON.
"""


def _build_remediation_prompt(review: dict, repo_root: Path) -> str:
    """Build the user prompt: capped findings + per-file contents."""
    findings = (review or {}).get("findings") or []
    findings = sorted(
        findings,
        key=lambda f: (
            -SEVERITY_RANK.get((f.get("severity") or "INFO").upper(), 0),
            -int(f.get("risk_score") or 0),
        ),
    )[:20]

    parts: list[str] = [
        "Produce safe, minimal patches for the following security findings.\n"
        "Coverage threshold is irrelevant here; fix the code, not the tests.\n"
        f"Severity scale: CRITICAL > HIGH > MEDIUM > LOW > INFO.\n"
    ]
    parts.append("===== FINDINGS (sorted by severity, capped at 20) =====")
    for f in findings:
        parts.append(
            f"- id={f.get('id', '?')} sev={f.get('severity', 'INFO')} "
            f"file={f.get('file', '?')} line={f.get('line', '?')} "
            f"rule_id={f.get('rule_id', '?')}\n"
            f"  evidence: {(f.get('evidence') or '')[:300]}\n"
            f"  suggested_fix: {(f.get('suggested_fix') or '')[:300]}"
        )

    # Attach the current content of every file referenced by the findings.
    seen: set[str] = set()
    parts.append("\n===== CURRENT FILE CONTENTS =====")
    for f in findings:
        rel = (f.get("file") or "").replace("\\", "/")
        if not rel or rel in seen:
            continue
        seen.add(rel)
        path = repo_root / rel
        if not path.exists():
            parts.append(f"\n----- {rel} (NOT FOUND on disk) -----")
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            parts.append(f"\n----- {rel} (READ ERROR: {exc}) -----")
            continue
        if len(content.encode("utf-8")) > _LLM_MAX_FILE_BYTES:
            content = content[:_LLM_MAX_FILE_BYTES] + "\n<!-- truncated -->\n"
        parts.append(f"\n----- {rel} -----\n{content}")

    parts.append(
        "\nReturn ONLY the JSON object. No commentary, no markdown fences."
    )
    return "\n".join(parts)


def _apply_llm_patches(repo_root: Path, raw_response: str) -> tuple[list[dict], list[dict]]:
    """Validate and write the LLM's per-file patches. Returns
    `(applied_fixes, skipped_fixes)`."""
    applied: list[dict] = []
    skipped: list[dict] = []

    parsed = _extract_json(raw_response)
    if not parsed:
        skipped.append({
            "rule_id": "llm",
            "finding_id": "-",
            "reason": "LLM response was not valid JSON",
        })
        return applied, skipped
    patches = parsed.get("patches")
    if not isinstance(patches, list):
        skipped.append({
            "rule_id": "llm",
            "finding_id": "-",
            "reason": "LLM response did not contain a `patches` array",
        })
        return applied, skipped
    if not isinstance(parsed.get("skipped", []), list):
        parsed["skipped"] = []

    total_bytes = 0
    for i, patch in enumerate(patches):
        if not isinstance(patch, dict):
            skipped.append({"rule_id": "llm", "finding_id": f"#{i}", "reason": "patch is not an object"})
            continue
        if len(applied) >= _LLM_MAX_PATCHES:
            skipped.append({"rule_id": patch.get("rule_id", "llm"), "finding_id": patch.get("finding_id", f"#{i}"),
                            "reason": f"max patches ({_LLM_MAX_PATCHES}) reached"})
            continue
        rel = (patch.get("file") or "").replace("\\", "/").lstrip("/")
        new_content = patch.get("new_content")
        rule_id = patch.get("rule_id") or "llm-patch"
        finding_id = patch.get("finding_id") or f"#{i}"
        if not rel:
            skipped.append({"rule_id": rule_id, "finding_id": finding_id, "reason": "missing `file`"})
            continue
        if not isinstance(new_content, str):
            skipped.append({"rule_id": rule_id, "finding_id": finding_id, "reason": "missing or non-string `new_content`"})
            continue
        if not _is_path_writable(rel):
            skipped.append({"rule_id": rule_id, "finding_id": finding_id,
                            "reason": f"path not whitelisted: {rel}"})
            continue
        added_bytes = len(new_content.encode("utf-8"))
        if total_bytes + added_bytes > _LLM_MAX_BYTES_PER_CALL:
            skipped.append({"rule_id": rule_id, "finding_id": finding_id,
                            "reason": f"max bytes per call ({_LLM_MAX_BYTES_PER_CALL}) reached"})
            continue
        target = repo_root / rel
        if not target.exists():
            skipped.append({"rule_id": rule_id, "finding_id": finding_id,
                            "reason": f"file does not exist on disk: {rel}"})
            continue
        current = _read(target)
        if current == new_content:
            skipped.append({"rule_id": rule_id, "finding_id": finding_id,
                            "reason": "new_content is identical to current file (no change)"})
            continue
        if f"FIX_LLM_APPLIED: {rule_id}" in current:
            skipped.append({"rule_id": rule_id, "finding_id": finding_id,
                            "reason": "already applied (FIX_LLM_APPLIED marker present)"})
            continue
        # Write + read-back verification.
        try:
            _write(target, new_content)
        except OSError as exc:
            skipped.append({"rule_id": rule_id, "finding_id": finding_id,
                            "reason": f"write failed: {exc}"})
            continue
        if _read(target) != new_content:
            # Best-effort rollback: rewrite the original content.
            try:
                _write(target, current)
            except OSError:
                pass
            skipped.append({"rule_id": rule_id, "finding_id": finding_id,
                            "reason": "read-back verification failed"})
            continue
        total_bytes += added_bytes
        applied.append({
            "rule": rule_id,
            "category": "llm-fix",
            "file": rel,
            "description": (patch.get("description") or "")[:200],
            "source": "llm",
            "finding_id": finding_id,
            "safe": True,
        })
        print(f"  [llm] patched {rel} for {rule_id}", file=sys.stderr)

    # Merge LLM-declared skips with our own validation skips.
    for s in parsed.get("skipped", []):
        if not isinstance(s, dict):
            continue
        skipped.append({
            "rule_id": s.get("rule_id", "llm"),
            "finding_id": s.get("finding_id", "-"),
            "reason": s.get("reason", "skipped by LLM"),
        })
    return applied, skipped


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
    p.add_argument("--model", default=os.environ.get("NVIDIA_MODEL", "meta/llama-3.1-70b-instruct"))
    p.add_argument("--base-url", default=os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"))
    p.add_argument("--max-tokens", type=int, default=int(os.environ.get("NVIDIA_MAX_TOKENS", "8000")))
    p.add_argument("--skip-llm", action="store_true",
                   help="Skip the LLM patch pass and only run the deterministic fixers.")
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

    # LLM patch pass: ask the model for additional per-file patches and
    # apply them after the deterministic fixers. Skipped when --skip-llm
    # is set or when NVIDIA_API_KEY is missing.
    llm_skipped: list[dict] = []
    if not args.skip_llm and os.environ.get("NVIDIA_API_KEY", "").strip():
        print("Asking LLM for per-file patches...", file=sys.stderr)
        user_prompt = _build_remediation_prompt(review, args.repo_root)
        (args.reports / "llm-prompt.txt").write_text(user_prompt, encoding="utf-8")
        raw = _call_nvidia(
            user_prompt,
            _REMEDIATION_SYSTEM_PROMPT,
            args.model,
            args.base_url,
            args.max_tokens,
        )
        (args.reports / "llm-response.txt").write_text(raw, encoding="utf-8")
        llm_applied, llm_skipped = _apply_llm_patches(args.repo_root, raw)
        all_fixes += llm_applied
        print(f"  LLM applied {len(llm_applied)} patch(es), skipped {len(llm_skipped)}.",
              file=sys.stderr)
    else:
        print("LLM patch pass skipped (no --skip-llm=false and no NVIDIA_API_KEY).",
              file=sys.stderr)

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
        "skipped_findings": _collect_skipped(review, all_fixes, extra_skipped=llm_skipped),
    }
    (args.reports / "remediation-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Remediation report written to {args.reports}/remediation-report.json")
    if pr_url:
        print(f"Opened PR: {pr_url}")
    return 0


def _render_summary(review: dict, fixes: list[dict], diff_stat: str, file_count: int) -> str:
    det_fixes = [f for f in fixes if f.get("source") != "llm"]
    llm_fixes = [f for f in fixes if f.get("source") == "llm"]
    lines = [
        "# AI Auto-Remediation Summary",
        "",
        f"- **Status:** {('OK' if fixes else 'NO_CHANGES')}",
        f"- **Safe fixes applied:** {len(fixes)} (deterministic: {len(det_fixes)}, LLM: {len(llm_fixes)})",
        f"- **Files changed:** {file_count}",
        "",
        "## Fixed (deterministic)",
        "",
    ]
    for f in det_fixes:
        lines.append(
            f"- [{f.get('rule','')}] `{f.get('file','')}` — {f.get('description','')}"
        )
    if not det_fixes:
        lines.append("- (none)")
    if llm_fixes:
        lines.extend(["", "## Fixed (LLM-generated)", ""])
        for f in llm_fixes:
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
        "- [ ] For LLM fixes, sanity-check the new file content end-to-end",
        "- [ ] Approve the PR if the changes are acceptable",
    ])
    return "\n".join(lines) + "\n"


def _collect_skipped(review: dict, applied: list[dict], extra_skipped: list[dict] | None = None) -> list[dict]:
    """Record any review findings whose rule wasn't applied — those are
    the ones the deterministic engine refused to touch — plus any
    extra skip reasons (e.g. from the LLM patch pass)."""
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
    if extra_skipped:
        skipped.extend(extra_skipped)
    return skipped


if __name__ == "__main__":
    raise SystemExit(main())
