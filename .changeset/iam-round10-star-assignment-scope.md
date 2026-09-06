---
'@gentleduck/iam': minor
---

Refuse `'*'` as the scope of a role *assignment*.

`'*'` is this package's spelling of "every scope" on the scope a role or a
permission **declares** — `IPermission.scope` is typed `TScope | '*'`, and
`matchesScope`, `scopeCovers` and `effectiveScopeOf` all read it as global. It
means nothing of the kind on a scoped **assignment**: `enrichSubjectWithScopedRoles`
compares the stored scope literally, so `assignRole(u, r, '*')` stored a row that
matched no request, while the write resolved and `admin.assignRoles` reported
`applied: 1`. `getEffectiveRoles` returned `[]`.

That is the same silent success `iamAssertNoAssignOptions` refuses for a dropped
`expiresAt` and `iamAssertRoleExists` refuses for an unknown role id, and
`assignRole`'s own contract already says a grant `resolveSubject` will drop must
throw rather than read back as success. `undefined` is how a global assignment is
spelled.

Lookups stay open: `revokeRole`, `revokeRoles`, the `fromScope` end of
`updateAssignmentScope` and redis's member encoder all accept `'*'`, so rows
written before this change can still be revoked or moved off. They were dead
before it and are dead after it; nothing that worked stops working.

The check also runs in `admin`'s pre-pass, not only in the adapters. The adapter
guard fires inside `assignRoles`' write loop, which would leave the batch
half-applied — the failure the pre-pass is documented to prevent.
