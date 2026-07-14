# AI Auto-Remediation Summary

- **Status:** OK
- **Safe fixes applied:** 1 (deterministic: 1, LLM: 0)
- **Files changed:** 1

## Fixed (deterministic)

- [outdated-base-image] `Dockerfile` — Added `apt-get upgrade -y` to runtime stage to remediate image-level OS-package CVEs (30 findings, e.g. bsdutils, gzip, libblkid1, libc-bin, libc6)

## Diff stat

```
Dockerfile | 1 +
 1 file changed, 1 insertion(+)
```

## Reviewer checklist

- [ ] Confirm no business logic was changed
- [ ] Run `mvn -B -ntp -Pcoverage verify` locally
- [ ] Review the unified diff in `ai-patch.diff`
- [ ] For LLM fixes, sanity-check the new file content end-to-end
- [ ] Approve the PR if the changes are acceptable
