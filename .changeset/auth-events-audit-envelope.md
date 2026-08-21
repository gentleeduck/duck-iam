---
'@gentleduck/auth': minor
---

Stamp an audit envelope onto every event that declares one.

The engine already wrapped its bus in `withAuditStamping`, but the module it comes from
was never published, so the package did not build from source. It ships now.

Two sources fill the envelope, in priority order: the ambient one opened by
`runWithAuditEnvelope()`, which an adapter wraps request handling in once the session is
resolved, then the emitted session's own `actingAs`. A payload that already carries
`audit` is left alone. Absent therefore means "no impersonation was in effect", not
"unknown", but only for events emitted inside a `runWithAuditEnvelope()` scope or
carrying a session.

The audited-event list is a total record over `Events.AuditedEvent`, so a new event
declaring `audit` fails to compile until it is listed, rather than silently going
unstamped.

`session.rotated` now carries `previousSessionId`, the hashed id of the session rotated
away from, present whenever the caller supplied a `previousSid`. Audit consumers use it
to chain a session's lineage across rotations.

`authz.revoked` is declared on the event map for the IAM side to publish and duck-auth
to subscribe to, so every instance can drop cached decisions. It carries no envelope
precisely because it does not originate here.

The wrap has to be explicit rather than happening inside `resolveSession`, because doing
it there needs `AsyncLocalStorage.enterWith`, which segfaults on Bun 1.3.14-canary.
