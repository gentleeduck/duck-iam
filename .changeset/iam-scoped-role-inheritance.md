---
'@gentleduck/iam': patch
---

Fix scoped role assignments not resolving inherited roles. `resolveSubject` closed
`subject.roles` over `inherits` but passed `subject.scopedRoles` through unresolved,
so a condition reading `subject.scopedRoles` saw only the directly assigned role and
not what it inherits, while the exact same role assigned without a scope resolved
correctly. Scoped roles now go through the same inheritance closure.

`IamClient` also gains `PartialPermissionMap`, the type `engine.permissions()`
actually returns (only the checked keys, not every possible combination). The React
client's `usePermissions`/`createIamPermissionChecker`/`IContextValue.permissions`
now use it instead of the full `PermissionMap`, matching what callers really have.
`iamBuildPermissionKey` is also re-exported from the React entry so a consumer
building a key by hand doesn't need a second import from core.
