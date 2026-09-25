# Actor context

Who a write is attributed to. Every mutable table in this package declares `created_by`, `updated_by`
and `deleted_by`, every adapter fills them from `actorId()`, and this module is what `actorId()` reads.

The value is opaque — a user id, a service account, `system`. It is written verbatim and never resolved,
so it need not name an identity in this database. When nothing is bound the answer is `null`: the columns
record that no actor was known, which is a statement rather than a placeholder standing in for one.

## Precedence

`actorId()` asks four questions in order and takes the first answer:

| | source | bound by |
| --- | --- | --- |
| 1 | the explicit argument | `actorId({ actorId: 'op-7' })` |
| 2 | the ambient scope | `withActor('op-7', fn)` |
| 3 | the process-wide default | `createAuth({ resolveActor })`, or `setDefaultActorResolver` |
| 4 | `null` | nothing bound, or an id that names nobody (`''`) |

Explicit beats ambient so one call inside a request can be attributed to someone other than the
request's own actor — an operator touching a user's row. Ambient beats the default because a request
that named its actor is more specific than a process-wide fallback.

`withActor(undefined, fn)` is a fence, not a no-op: it clears the scope for `fn` instead of inheriting
the one around it. `IdentitiesImpl.erase` relies on that, which is why it binds only when it actually
holds an operator id. The empty string is the same fence, so a host whose request context answers `''`
for "no user" records NULL rather than an account named nothing.

## Surface

**`actor.ts`** — the scope itself, over `AsyncLocalStorage`, mirroring `~/core/tenant`.

- `withActor(actorId, fn)` — binds the scope for `fn`, across awaits.
- `currentActor()` — the scope in force, `undefined` outside one.
- `resolveActor(explicit?)` — explicit over ambient, without the default or the `null`.
- `setDefaultActorResolver(resolve)` — installs the process-wide fallback; `undefined` clears it.
- `actorId(explicit?)` — the whole ladder above, as a `string | null`.

**`actor.request.ts`** — the per-request wrappers the framework adapters mount. Both attribute the
request to the operator behind `actingAs` while impersonating, since the column names the human
accountable, and to the session's own identity otherwise.

- `withRequestActor(auth, req, fn, opts?)` — resolves the session, binds the actor and the audit
  envelope, runs `fn` inside both.
- `withResolvedActor(session, fn, opts?, anomaly?)` — the same, for a caller that already resolved
  the session and should not pay for a second read.

**`actor.types.ts`** — `Actor.Context`, `Actor.Resolver`, `Actor.Resolvable`, `Actor.RequestOptions`.

## Wiring a request

Frameworks that compose a `next` get a middleware — `expressActorContext`, `koaActorContext`,
`honoActorContext`, `nestActorContext`; the rest get a wrapper you call around the handler —
`fastifyWithActor`, `elysiaWithActor`, `nextWithActor`, and gRPC's interceptor, which binds inline
because it has already resolved the session.

All of them end in `withRequestActor` or `withResolvedActor`, so the scope also carries the audit
envelope: an audited event emitted during the request records `admin X revoked user Y's session`
rather than a line indistinguishable from `user Y revoked their own`.

An app whose framework already carries a request context can skip the wrappers and wire
`createAuth({ resolveActor })` once. That is level 3 above, so a `withActor` inside a request still
wins over it.

## What this is not

**Not authorization.** Binding an actor grants nothing and refuses nothing. `withRequestActor` runs
`fn` unbound for an anonymous request and for one carrying a cookie that is expired, revoked or forged,
leaving the actor `null`. Refusing those is a guard's job. `opts.onSession` is the hook a guard uses: it
runs inside the scope, before `fn`, and throwing there refuses the request with any write it made first
still attributed.

**Not a place errors go quiet.** Anything other than "no session" — a store that is down, a session that
outlived its identity — is raised, not swallowed. Serving that request unbound would drop the actor, the
audit envelope and `onSession`'s hijack check together, silently, for as long as the store was unwell.

**Not fleet-safe as a default.** `setDefaultActorResolver` is module state: the last caller wins, so a
process running more than one engine should bind per request with `withActor` instead.

**Not forgiving of a broken resolver.** A `resolveActor` that throws is not caught. A broken actor
lookup is a wiring bug, and swallowing it would restore the NULL provenance this module exists to
remove.
