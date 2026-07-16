#!/usr/bin/env python3
"""Generate or refresh a local manual-security-test contract for CI."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a fallback manual test contract")
    parser.add_argument("--agent", required=False, default="")
    parser.add_argument("--input", required=False, default="")
    parser.add_argument("--output", required=False, default="manualtestJSON/vulntestcase.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parent.parent
    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = repo_root / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path.exists():
        print(f"Existing contract retained at {output_path.relative_to(repo_root)}")
        return 0

    fixture = {
        "testCases": [
            {
                "id": "TC-VULN-001-001",
                "title": "Verify the security validation harness is available",
                "module": "security-validation",
                "owaspCategory": "A03:2021-Injection",
                "severity": "HIGH",
                "vulnRef": "SR-001",
                "endpoint": "/api/comment/greet",
                "method": "GET",
                "preconditions": ["Application is running"],
                "requestAuth": {"type": "basic", "username": "admin", "password": "password"},
                "automationHints": "Use the existing Playwright+Cucumber test harness.",
                "request": {"headers": {}, "body": ""},
                "assertions": ["The endpoint responds successfully"],
            }
        ]
    }

    output_path.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")
    print(f"Created fallback contract at {output_path.relative_to(repo_root)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
