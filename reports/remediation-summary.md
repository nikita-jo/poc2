# AI Auto-Remediation Summary

- **Status:** OK
- **Safe fixes applied:** 1 (deterministic: 1, LLM: 0)
- **Files changed:** 10

## Fixed (deterministic)

- [outdated-base-image] `Dockerfile` — Added `apt-get upgrade -y` to runtime stage to remediate image-level OS-package CVEs (23 findings, e.g. bsdutils, libblkid1, libc-bin, libc6, libexpat1)

## Diff stat

```
Dockerfile                   |   1 +
 reports/SONAR_REPORT.md      |   8 +-
 reports/llm-prompt.txt       | 551 +++++++++++++++++++++++++++++++++++++++++--
 reports/security-report.json | 204 ++++++++++++----
 reports/security-review.json | 204 ++++++++++++----
 reports/security-review.md   | 137 ++++++++---
 reports/security-summary.txt |  20 +-
 reports/sonar-report.json    |   6 +-
 reports/trivy-image.raw.json | 350 +++++++++++++--------------
 reports/trivy-image.sarif    |   6 +-
 10 files changed, 1128 insertions(+), 359 deletions(-)
```

## Reviewer checklist

- [ ] Confirm no business logic was changed
- [ ] Run `mvn -B -ntp -Pcoverage verify` locally
- [ ] Review the unified diff in `ai-patch.diff`
- [ ] For LLM fixes, sanity-check the new file content end-to-end
- [ ] Approve the PR if the changes are acceptable
