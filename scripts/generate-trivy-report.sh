#!/usr/bin/env bash
#
# generate-trivy-report.sh
#
# Thin wrapper around the `trivy` CLI that produces the three files the
# pipeline expects from a filesystem scan:
#   <out-dir>/trivy-report.json  - normalised, structured findings
#   <out-dir>/trivy-report.txt   - human-readable summary
#   <out-dir>/trivy-fs.sarif     - SARIF for GitHub Security tab upload
#
# Usage:
#   generate-trivy-report.sh <out-dir> [<scan-path>]
#
# Env (optional):
#   TRIVY_SEVERITY  - default: CRITICAL,HIGH,MEDIUM,LOW
#   TRIVY_VERSION   - default: 0.58.1
#   SKIP_INSTALL    - if set, do not attempt to install the Trivy CLI
#
# Exit code: 0 always — Trivy findings are informational, not gating
# (matches the policy used elsewhere in the pipeline).
set -euo pipefail

OUT_DIR="${1:-reports}"
SCAN_PATH="${2:-.}"
SEVERITY="${TRIVY_SEVERITY:-CRITICAL,HIGH,MEDIUM,LOW}"
TRIVY_VERSION="${TRIVY_VERSION:-0.58.1}"

mkdir -p "$OUT_DIR"

# ---------------------------------------------------------------------
# Install Trivy if not present.
#
# Prefer the upstream install.sh (handles arch/OS detection correctly
# across versions). Fall back to a direct GitHub release download with
# the asset name current at the time of writing, and finally to apt.
# ---------------------------------------------------------------------
if ! command -v trivy >/dev/null 2>&1; then
  if [ -n "${SKIP_INSTALL:-}" ]; then
    echo "::error::Trivy not on PATH and SKIP_INSTALL is set; cannot scan."
    exit 1
  fi

  echo "Installing trivy ${TRIVY_VERSION} via upstream installer..."
  if ! curl -fsSL "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh" \
       | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}"; then
    echo "::warning::Upstream installer failed; trying direct GitHub release download..."
    # Asset names Trivy has shipped across versions:
    #   trivy_<ver>_Linux-64bit.tar.gz   (older)
    #   trivy_<ver>_linux-64bit.tar.gz   (older, lowercase)
    #   trivy_<ver>_linux_amd64.tar.gz   (current)
    for asset in \
      "trivy_${TRIVY_VERSION}_linux_amd64.tar.gz" \
      "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
      "trivy_${TRIVY_VERSION}_linux-64bit.tar.gz"; do
      url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${asset}"
      echo "  trying ${url}"
      if curl -fsSL -o /tmp/trivy.tgz "${url}"; then
        if tar -xz -C /usr/local/bin trivy -f /tmp/trivy.tgz; then
          rm -f /tmp/trivy.tgz
          echo "  downloaded ${asset}"
          break
        fi
      fi
    done
    if ! command -v trivy >/dev/null 2>&1; then
      echo "::warning::Direct download failed; falling back to apt..."
      apt-get update && apt-get install -y wget gnupg lsb-release apt-transport-https
      wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
        | gpg --dearmor -o /usr/share/keyrings/trivy.gpg
      echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" \
        > /etc/apt/sources.list.d/trivy.list
      apt-get update && apt-get install -y trivy
    fi
  fi

  if ! command -v trivy >/dev/null 2>&1; then
    echo "::error::Failed to install trivy. Set SKIP_INSTALL and pre-install, or pin TRIVY_VERSION to a release that ships an asset the install script can fetch."
    exit 1
  fi
  trivy --version
fi

echo "Running Trivy filesystem scan (${SCAN_PATH}) severities=${SEVERITY}"
# 1) SARIF for the GitHub Security tab
trivy fs \
  --quiet \
  --format sarif \
  --output "${OUT_DIR}/trivy-fs.sarif" \
  --severity "${SEVERITY}" \
  --no-progress \
  "${SCAN_PATH}" || true

# 2) Structured JSON — Trivy's own JSON output is richer than SARIF for diffing.
trivy fs \
  --quiet \
  --format json \
  --output "${OUT_DIR}/trivy-report.raw.json" \
  --severity "${SEVERITY}" \
  --no-progress \
  "${SCAN_PATH}" || true

# 3) Normalise the raw JSON into a flatter shape (used by the AI agents and
#    the diff script) using parse-sarif.py on the SARIF (the same findings,
#    same tool output, just easier to consume from Python).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${OUT_DIR}/trivy-fs.sarif" ] && command -v python3 >/dev/null 2>&1; then
  python3 "${SCRIPT_DIR}/parse-sarif.py" "${OUT_DIR}/trivy-fs.sarif" --tool trivy \
    > "${OUT_DIR}/trivy-report.json" || echo "[]" > "${OUT_DIR}/trivy-report.json"
fi

# 4) Plain-text summary for the artifact
if [ -f "${OUT_DIR}/trivy-report.json" ] && command -v python3 >/dev/null 2>&1; then
python3 - "${OUT_DIR}/trivy-report.json" "${OUT_DIR}/trivy-report.txt" <<'PYEOF'
import json, sys
from collections import Counter
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
try:
    findings = json.loads(src.read_text(encoding="utf-8"))
except Exception:
    findings = []

sev_counts = Counter(f.get("severity", "UNKNOWN") for f in findings)
cat_counts = Counter(f.get("category", "vulnerability") for f in findings)

lines = [
    "Trivy Filesystem Scan Summary",
    "=============================",
    "",
    f"Total findings: {len(findings)}",
    "",
    "By severity:",
]
for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
    lines.append(f"  {sev:9s} {sev_counts.get(sev, 0)}")
lines.append("")
lines.append("By category:")
for cat, n in cat_counts.most_common():
    lines.append(f"  {cat:15s} {n}")
lines.append("")
lines.append("Top 30 findings (sorted by severity, then by file):")
lines.append("-------------------------------------------------")
rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
for f in sorted(findings, key=lambda x: (-rank.get(x.get("severity", "UNKNOWN"), 0), x.get("file", "")))[:30]:
    where = f.get("file") or "(no file)"
    if f.get("line"):
        where = f"{where}:{f['line']}"
    line = f"[{f.get('severity','UNKNOWN'):8s}] {f.get('category','vuln'):10s} "
    if f.get("cve"):
        line += f"{f['cve']:18s} "
    if f.get("pkgName"):
        line += f"{f['pkgName']}"
        if f.get("installedVersion"):
            line += f"@{f['installedVersion']}"
        if f.get("fixedVersion"):
            line += f" -> {f['fixedVersion']}"
    else:
        line += f"{f.get('ruleId','')}"
    line += f"  -- {where}"
    lines.append(line)
if len(findings) > 30:
    lines.append("")
    lines.append(f"... and {len(findings) - 30} more (see trivy-report.json)")
dst.write_text("\n".join(lines) + "\n", encoding="utf-8")
PYEOF
fi

# 5) Always print a short summary to the run log
echo "Trivy scan complete. Findings:"
if [ -f "${OUT_DIR}/trivy-report.json" ]; then
  python3 -c "import json,sys; d=json.load(open('${OUT_DIR}/trivy-report.json')); s={}; [s.update({x.get('severity','UNKNOWN'):s.get(x.get('severity','UNKNOWN'),0)+1}) for x in d]; print('  CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d UNKNOWN=%d TOTAL=%d' % (s.get('CRITICAL',0),s.get('HIGH',0),s.get('MEDIUM',0),s.get('LOW',0),s.get('UNKNOWN',0),len(d)))"
fi
