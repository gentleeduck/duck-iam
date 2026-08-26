---
'@gentleduck/iam': patch
---

Drop `deletedAt` from `iamPolicies`, `iamRoles`, `iamAssignments`, and
`iamSubjectAttrs`, added in 5.5.0, along with `IamDrizzleAdapter`'s opt-in
`deletedAt IS NULL` read filtering. `deletePolicy`/`deleteRole`/`revokeRole` are
hard-delete by explicit design (a soft-deleted policy/role name couldn't be reused,
and a revoked assignment has no reason to be retained), and subject attributes have
no delete operation at all - none of these columns would ever have been set by
anything in this codebase.

`ops.isNull` stays on `IamDrizzleAdapter`'s config: `updateAssignmentScope` still
needs it to match a global (unscoped) assignment correctly, independent of the
removed soft-delete filtering.
