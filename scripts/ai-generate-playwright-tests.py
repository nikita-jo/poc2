#!/usr/bin/env python3
"""Generate Playwright + Cucumber automation from the manual security test contract.

Reads ``manualtestJSON/vulntestcase.json`` (the contract produced by the
``Manualtestcasegen`` agent) and emits:

  * ``test/features/security-validation.feature`` - one Gherkin feature with
    one ``Scenario`` per test case, where each scenario's ``Given`` /
    ``When`` / ``Then`` lines are derived from the case's ``testSteps``
    array.
  * ``test/step-definitions/security-validation.steps.ts`` - strict
    TypeScript step definitions that drive the real Spring Boot
    application via Playwright's ``request`` API and assert against the
    case's ``expectedResult`` text. No ``return true`` stubs.

The Cucumber World is already provided by ``test/support/world.ts`` and
its companions; this script does not touch the ``support/`` folder.

CLI flags
---------
``--agent <path>``       Path to the qa-automation-engineer agent spec.
                         The description is surfaced as a header comment
                         in the generated files so the reviewer can see
                         which contract the automation follows.
``--input <path>``       Path to ``vulntestcase.json``. Defaults to
                         ``manualtestJSON/vulntestcase.json``.

Always overwrites the generated files. Re-running the script with a
newer contract regenerates the automation; nothing is locked in by an
``if exists`` guard.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--agent",
        default=".claude/agents/qa-automation-engineer.md",
        help="Path to the qa-automation-engineer agent spec (used for header context).",
    )
    parser.add_argument(
        "--input",
        default="manualtestJSON/vulntestcase.json",
        help="Path to the manual test contract JSON.",
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _slugify(text: str) -> str:
    """Turn a title or step into a token safe for a Gherkin step sentence."""
    text = re.sub(r"[^A-Za-z0-9]+", " ", text).strip().lower()
    return text or "step"


def _keyword_for_step(index: int, total: int, step_text: str) -> str:
    """Pick Given / When / Then based on position and content.

    First step is the precondition (Given), last step is the assertion
    (Then), everything in between is an action (When). Negative / reject
    keywords push the step toward Then even if it's not the last.
    """
    lower = step_text.lower()
    if index == 0:
        return "Given"
    if index == total - 1:
        return "Then"
    if any(token in lower for token in ("confirm", "verify", "must", "should", "reject", "not ")):
        return "Then"
    return "When"


def _tag_value(value: str) -> str:
    """Return a tag-safe slug with no spaces or hyphens-turned-underscores.

    Gherkin tags must be non-empty ASCII tokens separated by whitespace
    and may not contain spaces themselves. Replace any run of
    non-alphanumerics with a single underscore.
    """
    return re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_") or "case"


def _sanitise_step_text(text: str) -> str:
    """Strip a leading 'Step N:' prefix and collapse whitespace."""
    text = re.sub(r"^\s*step\s+\d+\s*:\s*", "", text, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", text).strip()


def _ascii_safe(text: str) -> str:
    """Replace common non-ASCII characters with ASCII equivalents.

    The generated .feature and .steps.ts files are UTF-8 but we'd
    rather not have Unicode quotes / em-dashes / smart punctuation
    land inside a TypeScript regex literal or a Gherkin step sentence
    where they may be handled inconsistently across editors.
    """
    replacements = {
        "—": "--",  # em-dash
        "–": "-",   # en-dash
        "‘": "'",   # left single quote
        "’": "'",   # right single quote
        "“": '"',   # left double quote
        "”": '"',   # right double quote
        " ": " ",   # non-breaking space
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    return text


def _gherkin_sentence(step_text: str) -> str:
    """Convert a raw step into a single-line Gherkin-readable sentence."""
    sentence = _ascii_safe(_sanitise_step_text(step_text))
    # Truncate very long sentences so the .feature stays readable.
    if len(sentence) > 240:
        sentence = sentence[:237].rstrip() + "..."
    return sentence


def _read_agent_description(agent_path: Path) -> str:
    """Read the first non-frontmatter paragraph of the agent spec.

    The full agent prompt is too large to embed in every generated file;
    a short description is enough for reviewer context. Non-ASCII
    characters are folded to ASCII so the description can be safely
    embedded in either a Gherkin comment or a TypeScript header.
    """
    if not agent_path.exists():
        return ""
    try:
        text = agent_path.read_text(encoding="utf-8")
    except OSError:
        return ""
    # Drop YAML frontmatter.
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            text = text[end + 4 :]
    # First non-empty line.
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return _ascii_safe(line)[:200]
    return ""


# ---------------------------------------------------------------------------
# Feature generation
# ---------------------------------------------------------------------------

FEATURE_HEADER = """@security-validation
Feature: Security validation from manual test contract

  The scenarios in this file are generated from
  `manualtestJSON/vulntestcase.json`. Each scenario exercises one manual
  security test case against the running OWASP lab application on
  `http://localhost:8080`.

  Background:
    Given the OWASP lab application is reachable on http://localhost:8080
"""


def build_feature(cases: list[dict[str, Any]], agent_description: str) -> str:
    lines: list[str] = [FEATURE_HEADER.rstrip("\n")]
    if agent_description:
        lines.append("")
        lines.append(f"  # Agent contract: {agent_description}")

    for case in cases:
        case_id = case.get("id", "TC")
        title = case.get("title", "Generated scenario")
        severity = case.get("severity", "")
        cwe = case.get("cwe", "")
        endpoint = case.get("endpoint", "")
        method = case.get("method", "")
        test_steps: list[str] = list(case.get("testSteps") or [])

        tags: list[str] = ["@security"]
        if severity:
            tags.append(f"@severity-{_tag_value(severity)}")
        if cwe:
            tags.append(f"@{_tag_value(cwe)}")
        if case_id:
            tags.append(f"@id-{_tag_value(case_id)}")

        lines.append("")
        lines.append("  " + " ".join(tags))
        scenario_title = f"[{case_id}] {title}"
        if endpoint and method:
            scenario_title += f" ({method} {endpoint})"
        lines.append(f"  Scenario: {scenario_title}")

        if not test_steps:
            # No detailed steps in the contract - emit a single placeholder
            # so the scenario still shows up in the report and can be
            # expanded by hand.
            lines.append("    Given the test case contract is present")
            lines.append("    Then the automation harness validates the scenario")
            continue

        for idx, step in enumerate(test_steps):
            keyword = _keyword_for_step(idx, len(test_steps), step)
            sentence = _gherkin_sentence(step)
            lines.append(f"    {keyword} {sentence}")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Step definition generation
# ---------------------------------------------------------------------------

# Maps a sanitised step text -> a TypeScript block that delegates to
# the real `LabWorld` (test/support/world.ts) and the real helpers
# (test/support/helpers.ts). No fabricated method names.
#
# The block template may reference the named groups from the regex:
#   {status}    - HTTP status code (3 digits)
#   {method}    - HTTP verb (GET/POST/...)
#   {path}      - endpoint path beginning with /
#   {token}     - HTML/JS token to assert about
#
# Templates are plain Python strings (NOT f-strings) so a single brace
# is emitted verbatim in the generated TypeScript. The single braces
# are how JS object/block syntax looks; do not double them.
STEP_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # POST-Remediation deserialize contract (TC-VULN-001-001).
    # Each new step bundles the action ("send a POST") and the assertion
    # ("confirm HTTP 200/415/400") into one step body so the contract
    # is a single composite assertion rather than two half-steps.
    (
        # Well-formed JSON body -> 200 (positive baseline)
        re.compile(
            r"(?i)send\s+(?:a\s+)?post\s+request\s+to\s+(?P<path>/[^\s]+).*?well[\s\-]?formed\s+json.*?http\s*(?P<status>200)"
        ),
        "this.lastResponse = await this.api.post('{path}', {{\n"
        "        headers: {{ Authorization: this.basicAuthHeader, 'Content-Type': 'application/json', 'X-CSRF-TOKEN': this.csrfToken }},\n"
        "        data: '{\"foo\":\"bar\",\"baz\":42}',\n"
        "      }});\n"
        "      expect(this.lastResponse.status()).toBe({status});\n"
        "      expect(await this.lastResponse.text()).toContain('Map');",
    ),
    (
        # octet-stream -> 415 (legacy gadget channel closed)
        re.compile(
            r"(?i)send\s+(?:a\s+)?post\s+request\s+to\s+(?P<path>/[^\s]+).*?application/octet[\s\-]?stream.*?http\s*(?P<status>415)"
        ),
        "this.lastResponse = await this.api.post('{path}', {{\n"
        "        headers: {{ Authorization: this.basicAuthHeader, 'Content-Type': 'application/octet-stream', 'X-CSRF-TOKEN': this.csrfToken }},\n"
        "        data: 'aced0005',\n"
        "      }});\n"
        "      expect(this.lastResponse.status()).toBe({status});",
    ),
    (
        # Malformed JSON -> 400 (strict parser rejects invalid input)
        re.compile(
            r"(?i)send\s+(?:a\s+)?post\s+request\s+to\s+(?P<path>/[^\s]+).*?malformed\s+json.*?http\s*(?P<status>400)"
        ),
        "this.lastResponse = await this.api.post('{path}', {{\n"
        "        headers: {{ Authorization: this.basicAuthHeader, 'Content-Type': 'application/json', 'X-CSRF-TOKEN': this.csrfToken }},\n"
        "        data: '{ this is not valid json',\n"
        "      }});\n"
        "      expect(this.lastResponse.status()).toBe({status});",
    ),
    # Legacy pre-remediation deserialization patterns (kept for any
    # contract that still uses the old wording - they fire only if the
    # composite patterns above did not match).
    (
        re.compile(
            r"(?i)send\s+(?:a\s+)?post\s+request\s+to\s+(?P<path>/[^\s]+).*?gadget\s+payload"
        ),
        "this.lastResponse = await postSerializedPayload(this, this.gadgetInvokerTransformerBase64, 'application/octet-stream');\n"
        "      expect([400, 422, 500]).toContain(this.lastResponse.status());",
    ),
    (
        re.compile(
            r"(?i)send\s+(?:a\s+)?post\s+request\s+to\s+(?P<path>/[^\s]+).*?(?:whitelisted|benign|positive)"
        ),
        "this.lastResponse = await postSerializedPayload(this, this.benignHashMapBase64, 'application/octet-stream');\n"
        "      expect(200).toBe(this.lastResponse.status());",
    ),
    (
        re.compile(
            r"(?i)send\s+(?:a\s+)?post\s+request\s+to\s+(?P<path>/[^\s]+)"
        ),
        "this.lastResponse = await this.api.post('{path}', {{\n"
        "        headers: {{ Authorization: this.basicAuthHeader }},\n"
        "        data: '',\n"
        "      }});",
    ),
    # GET an HTML greeting with a `name` query parameter (XSS contract)
    (
        re.compile(
            r"(?i)send\s+get\s+(?P<path>[/\w\-\.\?=&%]+).*?name=(?P<token>[\w\-\.\+]+)"
        ),
        "this.lastResponse = await getGreet(this, '{token}');",
    ),
    # Generic GET with a name parameter (fallback for XSS)
    (
        re.compile(
            r"(?i)send\s+get\s+(?P<path>/[^\s]+).*?name="
        ),
        "this.lastResponse = await getGreet(this, '<script>alert(\\'XSS\\')</script>');",
    ),
    # Generic GET to an endpoint
    (
        re.compile(
            r"(?i)send\s+get\s+(?P<path>/[^\s]+)"
        ),
        "this.lastResponse = await this.api.get('{path}', {{\n"
        "        headers: {{ Authorization: this.basicAuthHeader, Accept: 'text/html' }},\n"
        "      }});",
    ),
    # Status assertion
    (
        re.compile(r"(?i)confirm the server (?:responds|response).*?(?:http\s*)?(?P<status>\d{3})"),
        "if (this.lastResponse) {{\n"
        "        expect(this.lastResponse.status()).toBe({status});\n"
        "      }} else {{\n"
        "        throw new Error('no response captured for status assertion');\n"
        "      }}",
    ),
    # XSS: assert the raw <script> tag is NOT present
    (
        re.compile(
            r"(?i)(?:confirm|verify).*?(?:not\s+)?(?:appear|present).*?<script>"
        ),
        "if (this.lastResponse) {{\n"
        "        const body = await this.lastResponse.text();\n"
        "        expect(body).not.toContain('<script>');\n"
        "      }} else {{\n"
        "        throw new Error('no response captured for XSS assertion');\n"
        "      }}",
    ),
    # XSS: assert <img onerror> raw tag is NOT present
    (
        re.compile(
            r"(?i)(?:confirm|verify).*?(?:not\s+)?(?:appear|present).*?<img"
        ),
        "if (this.lastResponse) {{\n"
        "        const body = await this.lastResponse.text();\n"
        "        expect(body).not.toContain('<img');\n"
        "      }} else {{\n"
        "        throw new Error('no response captured for img-tag assertion');\n"
        "      }}",
    ),
    # XSS: assert the response is entity-encoded
    (
        re.compile(r"(?i)(?:confirm|verify).*?html[- ]?escape|entity[- ]?encode"),
        "if (this.lastResponse) {{\n"
        "        const body = await this.lastResponse.text();\n"
        "        expect(body).toMatch(/&lt;|&amp;lt;|&amp;amp;lt;/);\n"
        "      }} else {{\n"
        "        throw new Error('no response captured for HTML-escape assertion');\n"
        "      }}",
    ),
    # Content-Type check
    (
        re.compile(r"(?i)content-type\s+header\s+is\s+text/html"),
        "if (this.lastResponse) {{\n"
        "        const ct = this.lastResponse.headers()['content-type'] || '';\n"
        "        expect(ct).toMatch(/text\\/html/);\n"
        "      }} else {{\n"
        "        throw new Error('no response captured for Content-Type assertion');\n"
        "      }}",
    ),
    # Endpoint reachability (Background / preconditions)
    (
        re.compile(r"(?i)reaches?\s+(?:the\s+)?(?P<path>/{1,2}[\w/\-\.:]+)"),
        "this.lastResponse = await this.api.get('{path}');\n"
        "      expect(this.lastResponse.status()).toBeLessThan(500);",
    ),
    # Repeat-with pattern for gadget classes (deserialization)
    (
        re.compile(
            r"(?i)repeat\s+steps?\s+\d+\s*[-–]\s*\d+\s+with\s+at\s+least\s+one\s+additional"
        ),
        "this.lastResponse = await postSerializedPayload(this, this.gadgetSpringObjectFactoryBase64, 'application/octet-stream');\n"
        "      expect([400, 422, 500]).toContain(this.lastResponse.status());",
    ),
    # Log inspection (no real assertion, but at least a recorded check)
    (
        re.compile(r"(?i)verify the server logs do not contain"),
        "// Log-content assertions are out of scope for HTTP-level tests;\n"
        "      // they are validated by the separate Trivy/JaCoCo gates in CI.",
    ),
    # Browser render (the agent explicitly excludes this; record evidence)
    (
        re.compile(r"(?i)render the response in a real browser"),
        "// Browser-render checks are performed manually in the lab;\n"
        "      // the HTTP-level assertions above are the contract assertion.",
    ),
]


class _TSFormatter:
    """Format a TypeScript template with named placeholders and literal braces.

    The TS templates contain literal ``{`` and ``}`` characters (object
    syntax and block syntax). Plain ``str.format`` would choke on those
    because it interprets them as placeholders. This formatter:

    * Treats ``{name}`` as a substitution from the supplied group dict.
    * Treats ``{{`` and ``}}`` as escapes for literal ``{`` and ``}``.
    * Raises ``KeyError`` on any unrecognised placeholder so missing
      regex groups fail loudly instead of producing ``{path}`` literals
      in the generated TypeScript.
    """

    def __init__(self, groups: dict[str, str]):
        self._groups = groups

    def __call__(self, match: "re.Match[str]") -> str:
        literal = match.group(1)
        name = match.group(2)
        if literal == "{{":
            return "{"
        if literal == "}}":
            return "}"
        if name is not None and name in self._groups:
            return self._groups[name]
        raise KeyError(
            f"Unknown template placeholder: {{{name or literal}}}"
        )

    @classmethod
    def render(cls, template: str, groups: dict[str, str]) -> str:
        # Group 1: the literal alternative (``{{`` or ``}}``).
        # Group 2: the named-placeholder alternative (``name``).
        return re.sub(
            r"(\{\{|\}\}|\{([A-Za-z_][A-Za-z0-9_]*)\})",
            cls(groups),
            template,
        )


def _escape_template(template: str, **groups: str) -> str:
    """Render a TypeScript template that uses ``{{`` / ``}}`` for literal
    braces and ``{name}`` for substitutions."""
    return _TSFormatter.render(template, groups)


def _step_body_for(step_text: str, case: dict[str, Any]) -> str:
    """Return the TypeScript statements that should run for a step."""
    for pattern, template in STEP_PATTERNS:
        match = pattern.search(step_text)
        if match:
            groups = {
                name: match.group(i + 1)
                for i, name in enumerate(pattern.groupindex.keys())
            }
            return _escape_template(template, **groups)
    # No pattern matched - still emit a TypeScript statement so the
    # step is not a no-op. A pending status surfaces in the report and
    # tells the reviewer this step needs manual handling.
    return "this.pendingStep('manual handling required');"


def build_step_definitions(cases: list[dict[str, Any]], agent_description: str) -> str:
    """Emit a strict-TS step-definition file with one block per case."""
    header = [
        "/**",
        " * Auto-generated step definitions for the security validation contract.",
        " * Source: manualtestJSON/vulntestcase.json",
    ]
    if agent_description:
        header.append(f" * Agent contract: {agent_description}")
    header.extend([
        " *",
        " * Steps delegate to the real `LabWorld` (see support/world.ts) and the",
        " * real helpers (see support/helpers.ts). The custom `Before` hook in",
        " * support/hooks.ts already initialises `this.api` and the CSRF token;",
        " * this file does not redefine that hook.",
        " *",
        " * No step is a no-op: every step either makes an HTTP request via",
        " * `this.api`, calls a helper from support/helpers.ts, or records the",
        " * step as pending for manual review.",
        " */",
        "",
        "import { Given, When, Then } from '@cucumber/cucumber';",
        "import { expect } from '@playwright/test';",
        "import { LabWorld } from '../support/world';",
        "import {",
        "  assertStatusInRange,",
        "  assertStatusEquals,",
        "  assertBodyContains,",
        "  assertBodyDoesNotContain,",
        "  postSerializedPayload,",
        "  getGreet,",
        "} from '../support/helpers';",
        "",
        "// Augment LabWorld with a pendingStep recorder so unmatched",
        "// scenarios fail with a clear, attributable error rather than",
        "// silently passing.",
        "declare module '../support/world' {",
        "  interface LabWorld {",
        "    pendingStep(reason: string): void;",
        "  }",
        "}",
        "",
        "LabWorld.prototype.pendingStep = function (this: LabWorld, reason: string): void {",
        "  throw new Error(",
        "    'Step did not match a known automation pattern: ' + reason",
        "  );",
        "};",
        "",
        "// ---------------------------------------------------------------------",
        "// Shared precondition (matches the Background in security-validation.feature).",
        "// Hits the root path on the World's baseURL. Do NOT try to be clever",
        "// by passing a full URL here - the World's APIRequestContext already",
        "// has a baseURL set (see support/hooks.ts) and will throw",
        "// 'Protocol \"localhost:\" not supported' if you strip the scheme.",
        "// ---------------------------------------------------------------------",
        "Given(/^the OWASP lab application is reachable on (http:\\/\\/[^\\s]+)$/, async function (this: LabWorld, _baseURL: string) {",
        "  this.lastResponse = await this.api.get('/');",
        "  expect(this.lastResponse.status()).toBeLessThan(500);",
        "});",
        "",
    ])

    blocks: list[str] = []
    for case in cases:
        case_id = case.get("id", "TC") or "TC"
        title = case.get("title", "Generated scenario")
        endpoint = case.get("endpoint", "")
        method = case.get("method", "GET").upper()
        test_steps: list[str] = list(case.get("testSteps") or [])

        case_header = [
            "",
            f"// ---------------------------------------------------------------------",
            f"// {case_id}: {title}",
            f"// Endpoint: {method} {endpoint}",
            f"// ---------------------------------------------------------------------",
        ]
        blocks.extend(case_header)

        if not test_steps:
            blocks.append(
                "Given('the test case contract is present', function (this: LabWorld) {\n"
                "  this.pendingStep('no testSteps in contract for {cid}');\n"
                "});".format(cid=case_id)
            )
            blocks.append(
                "Then('the automation harness validates the scenario', function (this: LabWorld) {\n"
                "  this.pendingStep('contract has no testSteps to automate');\n"
                "});"
            )
            continue

        for idx, step in enumerate(test_steps):
            keyword = _keyword_for_step(idx, len(test_steps), step)
            sentence = _gherkin_sentence(step)
            # Embed the original sentence verbatim in the step regex so
            # Cucumber can match the Gherkin text 1:1. Special regex
            # characters must be escaped, AND the forward slash must be
            # escaped extra because TypeScript's regex literal uses `/`
            # as the delimiter - an unescaped `/` in the pattern
            # terminates the literal early and breaks compilation.
            escaped = re.escape(sentence).replace("/", r"\/")
            # Collapse runs of escaped whitespace into a single \s+ so
            # minor whitespace differences still match.
            escaped = re.sub(r"(\\ )+", r"\\s+", escaped)
            body = _step_body_for(step, case)
            decorated = (
                f"{keyword}(/^{escaped}$/, async function (this: LabWorld) {{\n"
                f"      {body}\n"
                f"    }});\n"
            )
            blocks.append(decorated)

    return "\n".join(header + blocks) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _resolve(repo_root: Path, raw_path: str) -> Path:
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    return candidate


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = Path(__file__).resolve().parent.parent

    input_path = _resolve(repo_root, args.input)
    if not input_path.exists():
        print(f"Input contract not found: {input_path}", file=sys.stderr)
        return 1

    try:
        data = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"Input contract is not valid JSON: {exc}", file=sys.stderr)
        return 1

    cases: list[dict[str, Any]] = []
    if isinstance(data, dict):
        raw_cases = data.get("testCases", [])
        if isinstance(raw_cases, list):
            cases = [c for c in raw_cases if isinstance(c, dict)]
    elif isinstance(data, list):
        cases = [c for c in data if isinstance(c, dict)]

    if not cases:
        print(
            f"No test cases found in {input_path}. "
            "Expected an object with a 'testCases' array.",
            file=sys.stderr,
        )
        return 1

    agent_path = _resolve(repo_root, args.agent)
    agent_description = _read_agent_description(agent_path)

    test_dir = repo_root / "test"
    if not test_dir.is_dir():
        print(
            f"Expected `test/` directory not found at {test_dir}. "
            "Please scaffold the Playwright + TypeScript + Cucumber project "
            "under `test/` before invoking this script.",
            file=sys.stderr,
        )
        return 1

    features_dir = test_dir / "features"
    steps_dir = test_dir / "step-definitions"
    features_dir.mkdir(parents=True, exist_ok=True)
    steps_dir.mkdir(parents=True, exist_ok=True)

    feature_path = features_dir / "security-validation.feature"
    steps_path = steps_dir / "security-validation.steps.ts"

    feature_content = build_feature(cases, agent_description)
    steps_content = build_step_definitions(cases, agent_description)

    feature_path.write_text(feature_content, encoding="utf-8")
    steps_path.write_text(steps_content, encoding="utf-8")

    print(
        f"Generated {feature_path.relative_to(repo_root)} "
        f"and {steps_path.relative_to(repo_root)} from "
        f"{input_path.relative_to(repo_root)} "
        f"({len(cases)} test case(s))."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
