# Actor context

Who a write is attributed to. Identities carry `created_by`, `updated_by` and `deleted_by`, credentials
`created_by` and `updated_by`, provider links `added_by`; every adapter fills them from `actorId()`, and
this module is what `actorId()` reads. Sessions carry none.

The value is opaque — a user id, a service account, `system`. It is written verbatim and never resolved,
so it need not name an identity in this database. When nothing is bound the answer is `null`: the columns
record that no actor was known, which is a statement rather than a placeholder standing in for one.

## Precedence

`actorId()` asks three questions in order and takes the first answer:

| | source | bound by |
| --- | --- | --- |
| 1 | the ambient scope | `withActor('op-7', fn)` |
| 2 | the process-wide default | `createAuth({ resolveActor })`, or `setDefaultActorResolver` |
| 3 | `null` | nothing bound, or an id that names nobody (`''`) |

Ambient beats the default because a request that named its actor is more specific than a process-wide
fallback. The innermost scope wins, so one call inside a request is attributed to someone other than the
request's own actor — an operator touching a user's row — by a `withActor` around that call.

`withActor(undefined, fn)` is a fence, not a no-op: it clears the scope for `fn` instead of inheriting
the one around it. That is why `IdentitiesImpl.erase` binds only when it holds an operator id; binding
without one would erase as nobody inside a request that named its actor. The empty string is the same
fence, so a host whose request context answers `''` for "no user" records NULL rather than an account
named nothing.

## Surface

**`actor.ts`** — the scope itself, over `AsyncLocalStorage`.

- `withActor(actorId, fn)` — binds the scope for `fn`, across awaits.
- `setDefaultActorResolver(resolve)` — installs the process-wide fallback; `undefined` clears it.
- `actorId()` — the whole ladder above, as a `string | null`.

**`actor.request.ts`** — the per-request wrappers the framework adapters mount. Both attribute the
request to the operator behind `actingAs` while impersonating, since the column names the human
accountable, and to the session's own identity otherwise.

- `withRequestActor(auth, req, fn, opts?)` — resolves the session, binds the actor and the audit
  envelope, runs `fn` inside both.
- `withResolvedActor(session, fn, opts?, anomaly?)` — the same, for a caller that already resolved
  the session, or found none, and should not pay for a second read.

**`actor.types.ts`** — `Actor.Resolver`, `Actor.Resolvable`, `Actor.RequestOptions`.

## Wiring a request

Frameworks that compose a `next` get a middleware — `expressActorContext`, `koaActorContext`,
`honoActorContext`, `nestActorContext`; the rest get a wrapper you call around the handler —
`fastifyWithActor`, `elysiaWithActor`, `nextWithActor`, and gRPC's `withGrpc`.

A refusal, an `AuthError` below 500, reaches the client at its own status. `honoActorContext` and
`nextWithActor` answer it themselves, since Hono's default error handler and a Next route turn any throw
into a 500; gRPC maps it onto a status code; the rest hand it to the framework, which reads the status off
the error. A failure, such as a store that is down, is raised by the HTTP wrappers rather than answered,
for your error handling to see.

All of them end in `withRequestActor` or `withResolvedActor`, so the scope also carries the audit
envelope: an audited event emitted during the request records `admin X revoked user Y's session`
rather than a line indistinguishable from `user Y revoked their own`.

An app whose framework already carries a request context can skip the wrappers and wire
`createAuth({ resolveActor })` once. That is level 2 above, so a `withActor` inside a request still
wins over it.

## What this is not

**Not authorization.** Binding an actor grants nothing and refuses nothing. `withRequestActor` runs
`fn` as nobody for an anonymous request and for one carrying a cookie that is expired, revoked or
forged: both scopes are cleared rather than inherited from the one the server was started inside, so
the actor is the configured default or `null`. Refusing those is a guard's job. `opts.onSession` is the
hook a guard uses: it runs inside the scope, before `fn`, and throwing there refuses the request with
any write it made first still attributed, and before the anomaly verdict's `admit()`, so the detectors
learn nothing from it.

**Not a place errors go quiet.** Anything other than "no session" — a store that is down, a session that
outlived its identity — is raised, not swallowed. Serving that request unbound would drop the actor, the
audit envelope and `onSession`'s hijack check together, silently, for as long as the store was unwell.

**Not fleet-safe as a default.** `setDefaultActorResolver` is module state: the last caller wins, so a
process running more than one engine should bind per request with `withActor` instead.

**Not forgiving of a broken resolver.** A `resolveActor` that throws is not caught. A broken actor
lookup is a wiring bug, and swallowing it would restore the NULL provenance this module exists to
remove.
