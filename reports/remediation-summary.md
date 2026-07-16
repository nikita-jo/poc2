# AI Auto-Remediation Summary

- **Status:** OK
- **Safe fixes applied:** 2 (deterministic: 2, LLM: 0)
- **Files changed:** 9

## Fixed (deterministic)

- [hardcoded-secret] `src/main/resources/application.properties` — Removed hardcoded app.secret.* property
- [outdated-base-image] `Dockerfile` — Added `apt-get upgrade -y` to runtime stage to remediate image-level OS-package CVEs (22 findings, e.g. bsdutils, libblkid1, libc-bin, libc6, libexpat1)

## Diff stat

```
Dockerfile                                |   1 +
 reports/SONAR_REPORT.md                   |   8 +-
 reports/llm-prompt.txt                    |   9 +
 reports/sonar-report.json                 |   6 +-
 reports/trivy-image.raw.json              | 364 +++++++++++++++---------------
 reports/trivy-image.sarif                 |  12 +-
 reports/trivy-image.sarif.json            |   4 +-
 reports/trivy-report.json                 |   4 +-
 src/main/resources/application.properties |   6 +-
 9 files changed, 209 insertions(+), 205 deletions(-)
```

## Reviewer checklist

- [ ] Confirm no business logic was changed
- [ ] Run `mvn -B -ntp -Pcoverage verify` locally
- [ ] Review the unified diff in `ai-patch.diff`
- [ ] For LLM fixes, sanity-check the new file content end-to-end
- [ ] Approve the PR if the changes are acceptable
