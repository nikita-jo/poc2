# AI Auto-Remediation Summary

- **Status:** OK
- **Safe fixes applied:** 1 (deterministic: 1, LLM: 0)
- **Files changed:** 9

## Fixed (deterministic)

- [outdated-base-image] `Dockerfile` — Added `apt-get upgrade -y` to runtime stage to remediate image-level OS-package CVEs (23 findings, e.g. bsdutils, libblkid1, libc-bin, libc6, libexpat1)

## Diff stat

```
Dockerfile                     |   1 +
 reports/SONAR_REPORT.md        |   8 +-
 reports/llm-prompt.txt         |   9 +
 reports/sonar-report.json      |   6 +-
 reports/trivy-image.raw.json   | 439 ++++++++++++++++++++++++-----------------
 reports/trivy-image.sarif      |  80 ++++++--
 reports/trivy-image.sarif.json |  15 ++
 reports/trivy-report.json      |  16 ++
 reports/trivy-report.txt       |  10 +-
 9 files changed, 373 insertions(+), 211 deletions(-)
```

## Reviewer checklist

- [ ] Confirm no business logic was changed
- [ ] Run `mvn -B -ntp -Pcoverage verify` locally
- [ ] Review the unified diff in `ai-patch.diff`
- [ ] For LLM fixes, sanity-check the new file content end-to-end
- [ ] Approve the PR if the changes are acceptable
