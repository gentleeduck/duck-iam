---
'@gentleduck/iam': patch
---

Evaluation errors are now Indeterminate and fail closed instead of being silently skipped.

A condition that threw - an unknown operator, a malformed `all`/`any`/`none` group, a regex rejected for being unsafe - was caught and treated as "policy does not apply", which quietly retired the deny rule that condition was guarding. An error inside a policy or compiled cell that carries a deny rule now vetoes the request. Allow-only policies and RBAC role permissions still skip, since an error there cannot grant anything.

Also in this release:

- `matches` uses a real catastrophic-backtracking detector instead of a naive nested-quantifier regex, and checks the compiled-pattern cache before running it.
- Unknown condition operators and non-array condition groups throw a prefixed error rather than a raw `TypeError`.
- HTTP method-to-action and pathname normalisation reject `//admin` and `/%61dmin` style bypasses; unknown methods and unresolvable resources map to explicit `IAM_UNKNOWN_ACTION` / `IAM_UNKNOWN_RESOURCE` instead of a permissive default.
- User-Agent is capped at 2048 characters before it reaches the environment attributes.
- The file adapter writes atomically via tmp-file + rename and serialises concurrent flushes; the redis adapter rejects an empty scope; the drizzle adapter rejects non-finite assignment bounds.
- `preload()` builds the compiled table in production so a compile error surfaces at startup, and `healthCheck()` awaits it.
- `pathCache` is no longer exported from `src/core/resolve`.
