# AI Auto-Remediation Summary

- **Status:** OK
- **Safe fixes applied:** 3 (deterministic: 3, LLM: 0)
- **Files changed:** 10

## Fixed (deterministic)

- [sql-injection] `src/main/java/com/owasp/lab/service/UserService.java` — Parameterised native query that previously concatenated username into sql
- [plaintext-password] `src/main/java/com/owasp/lab/service/UserService.java` — loginUnsafe no longer concatenates password into the SQL; compares the password in Java with a TODO marker for BCrypt
- [outdated-base-image] `Dockerfile` — Added `apt-get upgrade -y` to runtime stage to remediate image-level OS-package CVEs (22 findings, e.g. bsdutils, libblkid1, libc-bin, libc6, libexpat1)

## Diff stat

```
Dockerfile                                         |   1 +
 reports/SONAR_REPORT.md                            |   6 +-
 reports/llm-prompt.txt                             |   9 +
 reports/sonar-report.json                          |   4 +-
 reports/trivy-image.raw.json                       | 541 ++++++++-------------
 reports/trivy-image.sarif                          | 242 +--------
 reports/trivy-image.sarif.json                     |  60 ---
 reports/trivy-report.json                          |  64 ---
 reports/trivy-report.txt                           |  10 +-
 .../java/com/owasp/lab/service/UserService.java    |  27 +-
 10 files changed, 242 insertions(+), 722 deletions(-)
```

## Reviewer checklist

- [ ] Confirm no business logic was changed
- [ ] Run `mvn -B -ntp -Pcoverage verify` locally
- [ ] Review the unified diff in `ai-patch.diff`
- [ ] For LLM fixes, sanity-check the new file content end-to-end
- [ ] Approve the PR if the changes are acceptable
