# AI Auto-Remediation Summary

- **Status:** OK
- **Safe fixes applied:** 1 (deterministic: 1, LLM: 0)
- **Files changed:** 9

## Fixed (deterministic)

- [outdated-base-image] `Dockerfile` — Added `apt-get upgrade -y` to runtime stage to remediate image-level OS-package CVEs (26 findings, e.g. bsdutils, libblkid1, libc-bin, libc6, libexpat1)

## Diff stat

```
Dockerfile                     |   1 +
 reports/SONAR_REPORT.md        |  10 +-
 reports/llm-prompt.txt         |   9 +
 reports/sonar-report.json      |   8 +-
 reports/trivy-image.raw.json   | 477 +++++++++++++++++++++--------------------
 reports/trivy-image.sarif      |  26 +--
 reports/trivy-image.sarif.json |  10 +-
 reports/trivy-report.json      |  10 +-
 reports/trivy-report.txt       |   2 +-
 9 files changed, 283 insertions(+), 270 deletions(-)
```

## Reviewer checklist

- [ ] Confirm no business logic was changed
- [ ] Run `mvn -B -ntp -Pcoverage verify` locally
- [ ] Review the unified diff in `ai-patch.diff`
- [ ] For LLM fixes, sanity-check the new file content end-to-end
- [ ] Approve the PR if the changes are acceptable
