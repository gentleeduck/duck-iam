---
'@gentleduck/iam': patch
---

Round out audit columns on the drizzle schema (pg/mysql/sqlite): `iamPolicies` and
`iamRoles` gain `deletedAt`; `iamSubjectAttrs` gains the `createdBy` it was missing
(it already had `updatedBy`) plus `deletedAt`. `iamAssignments`' own audit columns
are covered separately, alongside the new `updateAssignmentScope` feature that needs
them.

`IamDrizzleAdapter`'s `ops` config gains an optional `isNull` operator. When
provided, `listPolicies`/`getPolicy`/`listRoles`/`getRole`/`getSubjectRoles`/
`getSubjectScopedRoles`/`getSubjectAttributes` exclude rows with `deletedAt` set;
omitted (the default, matching every version before this column existed), reads are
unchanged. `deletePolicy`/`deleteRole`/`revokeRole` still hard-delete on purpose -
turning them into soft-deletes would break the unique-name constraint on policies/
roles (a "deleted" name couldn't be reused) and orphan the FK cascade from
`iamAssignments`. The column is a hook for something outside the adapter to set
(an admin tool, a trigger), not something this adapter writes itself.
