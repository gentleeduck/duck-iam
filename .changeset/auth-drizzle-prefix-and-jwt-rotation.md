---
'@gentleduck/auth': minor
---

Prefix the drizzle store table exports with `auth`, add keyed JWT transport
configuration with rotation support, and refuse the in-memory idempotency store
outside development.

**Renamed drizzle table exports** across `mysql`, `pg` and `sqlite`:

- `credentialsTable` is now `authCredentials`
- `identitiesTable` is now `authIdentities`
- `sessionsTable` is now `authSessions`
- `eventsTable` is now `authEvents`

The old names are gone, so update imports from
`@gentleduck/auth/adapters/drizzle/{mysql,pg,sqlite}`. Only the exported
bindings change — the physical table names are untouched, so no database
migration is required.

**Keyed JWT transport.** `jwtTransport` config is now a `JwtTransport` namespace
taking an explicit `signKey` plus the set of currently-valid `verifyKeys`, each
with a `kid` and per-key `alg` (HS256 by default, ES256 and RS256 via a PEM
private key). Keeping superseded keys in `verifyKeys` for an overlap window lets
already-issued tokens keep verifying through a rotation instead of failing at
cutover.

**`memoryIdempotency()` now throws** unless constructed with
`{ development: true }`, and always throws when `NODE_ENV` is `production`. Its
state is per-process, so it stops deduplicating as soon as a second instance
runs; it now fails loudly instead of degrading silently behind a load balancer.

The `@gentleduck/iam` peer range widens from an exact pin to `^`, so a minor iam
release no longer takes this package out of range.
