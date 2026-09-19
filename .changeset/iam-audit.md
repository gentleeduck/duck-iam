---
'@gentleduck/iam': minor
---

Authorization-correctness audit: behaviour fixes and the documentation defects
that were hiding them.

### The permission map allowed what `can()` denied

`permissions()` evaluated every check against a resource with no attributes,
while keying the answer by `resourceId`. A caller reads that key as an answer
about that instance, but a rule conditioned on `resource.attributes.*` could not
fire, so a deny written that way was invisible: `read:post:42` came back `true`
for the very row `can()` refuses.

`IamClient.IPermissionCheck` now takes an optional `attributes`, and each check
is evaluated against the attributes it carries. A check that omits them is
unchanged, and still answers about an instance that has none — now stated in the
reference instead of being inferred from the key.

The route guards had the same hole, and it was not structural. NestJS's
`iamNestAccessGuard` already accepted a `getResourceAttributes`; the express and
Hono `iamAccessMiddleware`s already took attributes synchronously through
`getResource`. The rest could not be told at all. Express and Hono's `iamGuard`,
`withIamAccess` and `createIamNextMiddleware` now take the same
`getResourceAttributes` option Nest has; `checkIamAccess` and the checker
`createIamSubjectCan` returns take the attributes as an argument. Supplying them
costs a load the guard exists to skip, so it stays opt-in: omit the callback and
the guard remains the coarse gate on type, id and scope, with the
attribute-dependent rule re-checked by `can()` once the row is in hand. All
eight surfaces are now pinned against one policy so they cannot drift apart.

### A route guard named the wrong row, or none

The guards that read the resource id read one path param, `id`, and could not be
told otherwise. On a nested route that names a different row: `/orgs/:id/posts/:postId`
guarded as a `post` sends the **org's** id as `resource.id`, so a rule denying a
particular post, or comparing `resource.id` against what the subject owns, was
answered about the wrong instance. Express and Hono's `iamGuard` and
`withIamAccess` now take the `getResourceId` option Nest already had; the default
is unchanged.

`createIamNextMiddleware` had no id at all. It matches a path prefix and knows
the rule's resource type, so a rule reading `resource.id` could not fire and the
request passed — the same fail-open shape as an attribute rule with no
attributes. It now takes `getResourceId` too, with no default, because only the
rule's own path shape says which segment is the id.

The resolved id is also handed to `getResourceAttributes` on every guard, so a
loader can fetch the row the check is actually about rather than re-deriving it.

### A Server Component check ignored the environment

`checkIamAccess` and `getIamPermissions` passed `undefined` where every other
integration passes a request-derived environment, and neither accepted one. A
policy keyed on `environment.ip`, `environment.userAgent` or a custom key read
as a non-match, so a deny that fired in Next middleware was inert in a Server
Component asking the same question. Both now take an `environment` argument and
forward it.

### A wedged database hung every admin call forever

`adapterTimeoutMs` is documented as a per-adapter-call timeout and was wired
only into the decision path. Against an adapter that never answers, `can()`
returned `false` as designed while every `engine.admin` call — including
`admin.listPolicies()`, the *same adapter method* `can()` bounds — never
settled. An admin route or dashboard hit a wedged database and hung, with no
error, no audit event, and nothing to say whether the write had landed.

All seventeen admin operations now run under the same timeout and reject with
the call named. Reads pass the abort signal through, so an adapter that honours
it cancels the query. Writes take no signal, so the timeout frees the caller
while the write runs on: a rejection means "not confirmed" rather than "not
applied", and every admin write is idempotent by id. The transaction-bound
admin stays unbounded on purpose — aborting mid-transaction leaves the
transaction for the caller to roll back — and that exclusion is now pinned by a
test rather than left to be rediscovered.

### An admin write over HTTP was recorded as nobody's

The admin routers authenticate a caller and hand it to their own audit hook.
They never handed it to `engine.admin`, so the engine's `onMutation` fired with
no actor and the SQL adapters wrote `created_by` / `updated_by` as null for
every request-driven write — the columns the drizzle and prisma schemas ship for
exactly this. An operator who wired `onMutation` instead of `onAdminMutation`
had no attribution at all, and nothing said so.

All four routers now forward a string `authorize` answer to `engine.admin`. An
object answer — a claims object, the documented common case — still names no one
to the engine, because its actor is a string and picking a field would be a
guess; the new `getMutationActor` option picks it. A value that names no one,
blank or non-string, is discarded rather than written.

`admin.import` had the same defect one layer down: it stamped its mutation
events with the actor it was given and passed nothing to `adapter.savePolicy` /
`saveRole`. It was the only admin write in the package that did. Fixed, and
every engine-side write is now pinned against a recording adapter so a new one
cannot be added without provenance.
