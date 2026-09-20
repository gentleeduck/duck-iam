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

### A dot in the resource type retired a `:*` deny

`resources: ['posts:*']` is documented to cover everything under `posts:`, and
it did — until the resource type contained a dot anywhere. The three evaluators
each switched to a dot-only matcher whenever either side contained a `.`, and
that matcher ignores `':*'` entirely. So a deny rule covering `posts:comment`
silently stopped covering `posts:comment.reply`: adding a dot to a resource
type removed it from every colon-wildcard rule in the policy set.

The policy-target level never switched, so the policy was still selected while
its own rule missed — the inconsistency that made it invisible.

All three evaluators (interpreter, compiled table, `explain()`) now use the
documented matcher, which reads the separator from the *pattern* and treats one
in the request as data. `.*` subtree matching, bare-literal behaviour and the
"a `:` pattern never matches a `.` type" rule are unchanged and pinned.
`matchesResourceHierarchical` stays exported as the strict dot-only variant and
is documented as no longer used by the engine.

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

### `preload({ validator: true })` never ran the validator

The flag loaded the lazy validate chunk and then dropped it on the floor: the
module was imported, `validatePolicy` and `validateRole` were never called, and
`preload()` resolved. Since `engine.admin` is the only thing that validates —
all six adapters call the same write gate, the read path validates nothing — a
row that entered storage another way (a migration, a seed script, a restore, a
direct SQL insert, another service writing the same table) was loaded and
evaluated exactly as stored, and nothing in the package could tell an operator.

Which matters because the two failure modes differ. A condition the evaluator
refuses is Indeterminate and the policy denies: loud, fail-closed, visible on
the first request. A row that merely never matches — an action carrying a
trailing newline from a CSV import, an unreachable resource pattern — just
misses, so a **deny** in that shape silently never fires and the request is
allowed.

`preload({ validator: true })` now reads the roles too and validates every
stored policy and role, throwing once with the exact number of offending rows
and up to ten named with their reason. Only `type: 'error'` issues fail the
boot; a `BROAD_ALLOW` warning does not. Without the flag `preload()` reads no
roles and runs no validator, so the cost stays opt-in.

### A route guard could not name the tenant it was deciding in

The access request has four dimensions — action, resource type, row, scope —
and the scope was the one no guard could derive from the request. `iamGuard`
(express and hono), `withIamAccess` and `createIamNextMiddleware` took only a
fixed `scope` fixed at mount time, so on the canonical multi-tenant route,
`/orgs/:orgId/posts/:postId`, every check ran with `scope: undefined` even
though the tenant was in the path. Only the nest guard could already read one
per request.

Running unscoped is not neutral in either direction. A scoped assignment —
`assignRole('u1', 'editor', { scope: 'org-1' })` — only enriches the subject
when the request carries a matching scope, so the grant did not apply and the
guard denied a caller who genuinely held the role. A rule conditioned on
`scope` is the opposite: the field resolves to `null`, the condition does not
match, and a **deny** in that shape silently never fired.

All four now take `getScope`, matching the extractor the two
`iamAccessMiddleware` surfaces already had and the shape nest already used. A
fixed `scope` still wins where both are given, so existing mounts keep their
meaning, and the resolved scope is handed to `getResourceAttributes` so an
attribute loader can read the row from the right tenant.

### A fail-closed deny told the observers nothing

`afterEvaluate`, `onDeny` and `onMetrics` fired for every verdict the evaluator
produced — and for none of the verdicts the engine produced without reaching
it. A malformed `subjectId` was refused silently, with no hook at all. An
adapter that would not answer fired `onError` and then denied, unobserved.
`permissions()` returned an all-`false` map on a batch load failure after one
`onError`, and a `false` per check that threw with only a metric.

These are exactly the denials worth watching. During an adapter outage the
engine refuses every request while `iamCreateMetricsAggregator().snapshot()`
held `total` and `deny` flat — an authorization failure that reads on a
dashboard as a traffic drop rather than a deny spike, and a security log fed by
`onDeny` that records nothing for the whole window.

Every verdict now reaches the observers. `decision.failure` names the path:
`'input'` for a malformed subject id, `'resolution'` for a subject or policy
load that threw, `'evaluation'` for a throw mid-check. `permissions()` emits one
per map entry, because there is one verdict per map entry, and
`{ telemetry: false }` still reports the deny while skipping the metric, as it
already did on the evaluated path. A malformed id does not also fire `onError`:
it is input, not a fault.

### A mistyped `scopeCombine` widened the role set

`policyCombine` has a boot-time guard because both evaluators branch on one
literal and fall through to the most permissive option for anything else. The
two scope settings have the identical shape and had no guard at all.

`scopeCombine` is the sharper of the two, because its fall-through is the
*wider* branch. A subject holding `admin` at `org-1` and `viewer` at
`org-1.team-a`, checked at `org-1.team-a` under `scopeMode: 'hierarchical'`,
resolves to `['viewer']` with `'override'` and to `['admin', 'viewer']` with
anything that is not that exact string — so `'overide'` in a config file
silently handed the caller every ancestor scope's roles, and `can('delete')`
flipped from `false` to `true`. `scopeMode` falls through to `'flat'`, which is
narrower, but it still means a hierarchical deployment quietly stops honouring
descendant scopes.

Both are now refused at construction with the same message shape as
`policyCombine`, so a bad value is a failed start rather than a quiet change of
meaning.
