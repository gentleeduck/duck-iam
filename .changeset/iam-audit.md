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

### A mistyped `mode` turned every deny into an allow

`IConfig.mode` was assigned with a bare `?? 'production'` and never checked,
while every site that reads it compares `this._mode === 'production'`. So
`'prodution'` did not fail, and did not run production either — it selected
development behaviour at all nine sites at once.

The worst of those is `check()`. In development it answers an `IDecision`
object instead of a bare boolean, and that object is truthy even when it
denies, so `if (await engine.check(...))` admitted every denial. TypeScript
could not catch it: `TMode` is a type argument that `mode` does not have to
agree with, so the call site still read as `boolean`. `explain()` also became
callable, exposing policy ids, rule ids and condition values in what the
operator believed was production, and the existing
`mode: 'production'` + `policyCombine: 'first-applicable'` guard was bypassed,
because the typo is not the string that check compares against.

`mode` is now refused at construction with the same message shape as
`policyCombine`, which also closes the `first-applicable` bypass.

### `constructor` and `toString` were usable as condition operators

`evalCondition` dispatched with a bare `ops[cond.operator]` and then checked
`typeof op !== 'function'`. `ops` is an object literal, so every
`Object.prototype` member is a function on it and passed that check.
`constructor` returned a boxed object and `toString` returned the string
`"[object Undefined]"` — both truthy — so the condition reported as satisfied
without ever comparing anything.

A rule carrying one fired unconditionally: an allow rule granted, and a deny
rule guarded by `none` was retired. It happened in both modes, because the fast
path's `conditionMayThrow` had already classified these names correctly — it
uses `Object.hasOwn` — and handed the policy to the interpreter, which is where
the truthy answer came from.

The write-path validator refuses these names, so only a row that reached
storage another way — a seed, a migration, a direct write — could carry one.
That is the same gap `preload({ validator: true })` exists to close.

Dispatch is now own-property only in `evalCondition`, in the interpreter's
combining-algorithm lookup, and in the public `iamEvaluateOperator`, which
previously let a policy linter report such a condition as satisfied.

### A mistyped `deny` was outvoted by its own policy's allow

`IRule.effect` is typed `'allow' | 'deny'`, and every branch that reads it tests
both names positively. An earlier fix made an unrecognised effect vote for
neither side, which is fail-closed for a policy whose *only* rule carries it —
nothing matches, so `defaultEffect` answers — and that is the shape that was
tested.

Give that deny a sibling allow in the same policy and it inverts. Measured, one
`deny-overrides` policy with an unconditional allow and a second rule spelled
`'DENY'`: `can()` answered **true**, against `false` for `'deny'`. The compiled
table agreed, by a different route: its flat model reads a non-allow effect as a
deny, so the cell became DYNAMIC, and the DYNAMIC cell asks the combiners, which
read it as neither.

An unrecognised effect is now Indeterminate rather than an abstention, which is
the same rule already applied to an unanswerable condition and an unknown
combining algorithm. `policyHasDenyRule` counts anything that is not `'allow'`,
so the Indeterminate denies instead of casting `defaultEffect`, and the policy
is reported through `onPolicyError` naming the offending rule.

The write path refuses these rows, so only a seed, a migration or a direct write
can carry one.

### A deny with a broken priority was outranked by every allow

`first-match` and `highest-priority` rank matched rules by `rule.priority`.
`rulePriority` read a priority that was not a finite number — `NaN`, `null`,
`'urgent'`, or absent — as `0`. That is a real rank, the lowest meaningful one,
so the rule stayed in the ranking and lost to any allow above it.

Measured, a `highest-priority` policy holding an unconditional allow at priority
5 and a deny carrying `'urgent'`, `-Infinity` or no priority at all: `can()`
answered **true** in both evaluators, against `false` for the same deny at
priority 9. Reading it as `-Infinity` loses the same way.

A priority the engine cannot rank is now Indeterminate, matching the rule
already applied to an unanswerable condition, an unknown combining algorithm and
an unrecognised effect. Both evaluators refuse it at policy level, after the
NotApplicable tests they already share, so they refuse exactly the same
requests; the compiled table's flat model never reads `priority`, so such a
policy is forced out of it. `deny-overrides` and `allow-overrides` do not rank,
and are unaffected.

The write path refuses these rows, so only a seed, a migration or a direct write
can carry one.

### Production allowed what development denied for a rule with no conditions object

`IRule.conditions` is required, and `evalConditionGroup` refuses anything that
is not a condition group. The fast path's `conditionMayThrow` classifier
disagreed: it read a node that is not an object — `undefined`, `null`, a string,
a number — as a leaf that cannot throw. So `idx.mayThrow` stayed false, the fast
path scanned the policy itself instead of handing it to the interpreter, and
`allow-overrides` returned on its first unconditional allow without ever
reaching the broken rule.

Measured, an `allow-overrides` policy with an unconditional allow and a deny
whose `conditions` was absent, `null` or a string, made residual by a `*`
resource: `can()` answered **false** in development and **true** in production.
The same shape nested one level down (`{ all: [null] }`) behaved the same way.

A non-object node is now a throw site at every depth, so the fast path delegates
and both modes refuse identically.

`evalConditionGroup` also reports it properly. `'all' in group` raises a bare
`TypeError` on a non-object, which is Indeterminate to a caller but arrives
without a duck-iam message — and it fired before the branch written to describe
a non-object could run, so that branch was unreachable. The non-object test now
runs first and throws `IamConditionGroupError('unknown-keys')` naming what it
saw.

The write path refuses these rows, so only a seed, a migration or a direct write
can carry one.

### `explain()` disagreed with the decision it was explaining

`explain()` reaches its verdict through its own combiner switch and its own
target matching, which makes it a third evaluator — and nothing compared it to
a verdict. Adding that comparison to the 6000-catalog differential found five
disagreements.

Reported **allow** where `can()` denied: an unrecognised `rule.effect` (the
combiner matches `'deny'` and `'allow'` positively, so a mistyped one voted for
neither) and a non-finite `rule.priority` (never checked at all). An unknown
combining algorithm fell off the end of the switch and raised
`Cannot destructure property 'effect'` out of `explain()` itself, so the
diagnostic crashed on exactly the input it exists to explain.

Reported **deny** where `can()` allowed: a throwing condition on a rule that
does not target the request poisoned the whole policy, though `ruleApplies`
never evaluates such a rule's conditions; and a throwing permission inside the
allow-only RBAC union was not allowed to abstain, though the decision path lets
it.

The policy-level refusals now come from one place and run behind the same
rule-target test the two evaluators share. `explain()` answers `defaultEffect`
directly when no rule matched, so the combining algorithm is never consulted
where it has no arm, and the hand-copied policy target matcher is gone in
favour of `policyApplies`. A non-object condition group is reported by name in
the trace rather than as a bare `TypeError`.
