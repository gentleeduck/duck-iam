---
'@gentleduck/iam': minor
---

**Breaking:** scoped permission keys are now prefixed with `@`.

`iamBuildPermissionKey` previously emitted `scope:action:resource[:resourceId]`, which is ambiguous with the unscoped `action:resource:resourceId` form - a three-segment key could not be parsed back without knowing which shape produced it, so a scope could be read as a resource id and vice versa. Scoped keys now carry an explicit `@` marker:

- `org-1:manage:billing` becomes `@org-1:manage:billing`
- `org-1:update:post:post-42` becomes `@org-1:update:post:post-42`

Unscoped keys are unchanged. A literal leading `@` in a segment is escaped as `\@`, and `iamSplitPermissionKey` understands the escape. The new `iamParsePermissionKey` returns `{ scope, action, resource, resourceId }` or `null`, so consumers no longer have to split keys by hand.

Anything that hardcodes a scoped key string - client-side permission maps, cached `can()` results keyed by string, fixtures - needs the `@` added.
