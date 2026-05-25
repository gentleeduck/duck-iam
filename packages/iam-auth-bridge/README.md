# @gentleduck/iam-auth-bridge

Thin glue between `@gentleduck/auth` and `@gentleduck/iam`. Lazy-subject middleware factory, default `IamProjection`, org-scoped variant, and the default impersonation policy.

> **Status:** 0.1.0 scaffold. See `packages/duck-auth/DESIGN.md` §7 / §38 / §43 for the spec.

## Why a third package?

Apps wanting auth-only or iam-only never import the bridge. Apps wanting both install all three. Either parent package can major-bump without dragging the other along.

```
@gentleduck/iam              ← zero auth knowledge
@gentleduck/auth             ← zero iam knowledge
@gentleduck/iam-auth-bridge  ← peerDep on both
```

## License

MIT — GentleDuck
