---
"@gentleduck/iam": minor
---

Add optional scope parameter to grant() for permission-level scoping

The `grant()` method now accepts an optional third `scope` argument:
`.grant('update', 'post', 'org-1')`. This enables permission-level
scoping directly without needing `grantScoped()`. The existing
`grantScoped(scope, action, resource)` method remains available.

Also fixed incorrect `first-applicable` references in JSDoc comments
to use the correct algorithm names `first-match` and `highest-priority`.
