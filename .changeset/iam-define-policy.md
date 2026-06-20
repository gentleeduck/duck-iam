---
'@gentleduck/iam': major
---

Rename the policy builder factory to `definePolicy`, matching `defineRule` and
`defineRole`.

BREAKING: the `policy()` factory and `access.policy()` method are removed. Use
`definePolicy()` and `access.definePolicy()` instead - the builder API is
otherwise unchanged.
