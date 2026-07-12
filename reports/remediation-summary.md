# AI Auto-Remediation Summary

- **Status:** OK
- **Safe fixes applied:** 4
- **Files changed:** 3

## Fixed

- [hardcoded-secret] `src/main/resources/application.properties` — Removed hardcoded app.secret.* property
- [sql-injection] `src/main/java/com/owasp/lab/service/UserService.java` — Parameterised native query that previously concatenated username into sql
- [plaintext-password] `src/main/java/com/owasp/lab/service/UserService.java` — loginUnsafe no longer concatenates password into the SQL; compares the password in Java with a TODO marker for BCrypt
- [missing-csp] `src/main/java/com/owasp/lab/config/SecurityConfig.java` — Added a default Content-Security-Policy header

## Diff stat

```
.../java/com/owasp/lab/config/SecurityConfig.java  |  3 ++-
 .../java/com/owasp/lab/service/UserService.java    | 27 +++++++++++++++-------
 src/main/resources/application.properties          |  6 ++---
 3 files changed, 24 insertions(+), 12 deletions(-)
```

## Reviewer checklist

- [ ] Confirm no business logic was changed
- [ ] Run `mvn -B -ntp -Pcoverage verify` locally
- [ ] Review the unified diff in `ai-patch.diff`
- [ ] Approve the PR if the changes are acceptable
