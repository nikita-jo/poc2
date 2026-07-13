# AI Auto-Remediation Summary

- **Status:** OK
- **Safe fixes applied:** 1 (deterministic: 0, LLM: 1)
- **Files changed:** 1

## Fixed (deterministic)

- (none)

## Fixed (LLM-generated)

- [CVE-2026-22732] `pom.xml` — Upgrade Apache Tomcat, Spring Security, and Jackson Databind to fix remote code execution vulnerabilities

## Diff stat

```
pom.xml | 200 ++++------------------------------------------------------------
 1 file changed, 11 insertions(+), 189 deletions(-)
```

## Reviewer checklist

- [ ] Confirm no business logic was changed
- [ ] Run `mvn -B -ntp -Pcoverage verify` locally
- [ ] Review the unified diff in `ai-patch.diff`
- [ ] For LLM fixes, sanity-check the new file content end-to-end
- [ ] Approve the PR if the changes are acceptable
