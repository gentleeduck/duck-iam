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

### A role grant retired an explicit deny under `first-applicable`

`policyCombine: 'first-applicable'` stops at the first policy that is not
NotApplicable, so whichever policy comes first is the decision. `loadAllPolicies`
handed over the synthetic `__rbac__` policy first — a policy the operator never
wrote, generated from the role definitions.

It is applicable to any action/resource pair *any* role grants, so it decided
both ways it should not have. A subject holding a role that grants
`delete` on `post` got that allow and never reached the ABAC policy denying a
locked post: granting a role widened access past an explicit deny. A subject
holding no such role got the RBAC policy's `defaultEffect` deny and never
reached an ABAC policy that would have allowed.

The generated policy now goes last, in `evaluate` and in `explain`'s
`decideFinal` through one shared helper, so the trace and the decision cannot
name different policies. `'and'` and `'allow-overrides'` fold every applicable
vote and are unchanged. The order of the stored policies themselves is still the
adapter's row order, as it is for rule order, and no adapter orders
`listPolicies`.

### A mistyped action in a policy rule was reported for roles and not for policies

`createIam` constrains `engine.check` to the declared action and resource
unions, so anything a rule names outside them can never be requested.
`createIam(...).validateRoles` has always reported that for a grant —
`UNREACHABLE_TARGET`, an error. `createIam(...).validatePolicy` did not pass the
vocabulary through at all, so the same typo in a policy rule returned
`valid: true`.

The direction that matters is the deny. A policy that allows `'*'` on `post`
and means to deny `delete`, written `actions: ['delet']`, answers `can('delete',
'post')` with `true`; spelled correctly it answers `false`. Nothing reported it.

`validatePolicy` now takes the same optional declared surface and checks
`rule.actions`, `rule.resources`, `targets.actions`, `targets.resources` and
`targets.roles`. Patterns are cleared through the engine's own `matchesAction`
and `matchesResource`, so a prefix is accepted on exactly the values it would
match at runtime and the action axis's lack of a dot form is honoured. The bare
`validatePolicy` export is unchanged, as the bare `validateRoles` is.

### A role grant the engine honours was reported as unreachable

The vocabulary pass `createIam(...).validateRoles` runs matched a grant against
the declared list with `includes`, so only a literal or `'*'` could clear it.
`validateRoles` takes the **unconstrained** `IRole` on purpose — it exists for
rows read from a store, a config file or an admin form — and the engine honours
a prefix pattern in a role permission: `{ action: 'post:*', resource: 'org.*' }`
grants `post:create` on `org.team` and nothing else.

That grant came back `valid: false` with two `UNREACHABLE_TARGET` errors, which
`PolicyBuilder`-style callers and admin UIs read as a refusal. Each axis is now
cleared by the matcher the engine actually uses — `matchesAction`,
`matchesResource`, `matchesScope` — so `'post:*'` and `'org.*'` pass, while
`'admin.*'` on the action axis is still reported (there is no dot form there)
and `'org-1.*'` as a scope is still reported (scopes match exactly).

### A non-string entry in `policy.targets` retired the policy, or the whole engine

`validatePolicy` type-checked every entry of `rule.actions` and `rule.resources`
— string, no control characters — and checked `targets.actions`,
`targets.resources` and `targets.roles` only for `Array.isArray`. Not one entry
inside them was looked at, and the vocabulary pass skipped a list that was not
already all strings, so a malformed target was the one corner nothing read.

Both outcomes are reachable from a policy the validator called `valid: true`:

- **A target the roles axis cannot match retires the policy's denies.**
  `targets.roles` is compared with `includes`, so a number — or a role id
  carrying a stray control character — matches no subject. The policy becomes
  NotApplicable for everyone and the deny inside it never runs. Measured with a
  policy that allows `'*'` and denies a locked resource: with
  `targets: { roles: ['editor'] }` the locked request answers `false`; with
  `roles: [42]` it answers `true`.
- **A target on the action or resource axis takes the process down.**
  `matchesAction` calls `.endsWith` on the pattern, so a number throws while the
  compiled table is being built. The engine fails closed and warns, but every
  request in that process is denied until the row is removed.

Entries are now checked the way rule entries always were, per axis and per
index, so the write path refuses the row: `savePolicy` reports
`targets.roles[0] must be a string`. Rows already in a store are not
re-validated, so the runtime behaviour above is pinned by tests rather than
changed.

### The published policy schema refused four shapes the validator accepted

`POLICY_JSON_SCHEMA` is published so operators can gate policies in an admin UI
or in CI, and its contract is one-directional: anything it rejects,
`validatePolicy` rejects too, so a policy the runtime accepts always validates
there. Four shapes broke that, all of them fields `IPolicy` and `IRule` already
type:

| Shape | `validatePolicy` | schema |
| --- | --- | --- |
| `description` on a policy, not a string | accepted | rejected |
| `description` on a rule, not a string | accepted | rejected |
| `metadata` on a rule, not an object | accepted | rejected |
| `targets: null` | accepted | rejected |

`description` and `metadata` were listed in the known-key sets and type-checked
nowhere; `targets: null` was explicitly skipped. The validator now checks all
four, which is the side that was wrong — no adapter produces any of them (both
drizzle and prisma drop a null column rather than passing it on), and `explain()`
renders a rule `description` into the trace it hands an operator.

**Behaviour change:** `savePolicy`, `admin.import()` and `PolicyBuilder.build()`
now refuse a policy carrying `targets: null` or a non-string `description`.
TypeScript callers cannot write any of these shapes; plain-JS and JSON callers
that did were writing a policy the published schema already rejected.

### The fuzzer pinning that contract tested it on 147 policies out of 4000

The randomised half of `schema-validator-agreement.test.ts` generated each slot
independently from its own pool, so almost every policy was invalid for some
unrelated reason and never reached the implication under test — `validatePolicy`
accepted 147 of 4000. `targets` was not in the generator at all (one constant,
`{ actions: ['read'] }`), and `description`, `metadata` and `priority` were
constants too, which is why the four shapes above survived 4000 passes a round.

Its non-vacuity guard asked a *different*, simpler generator whether it produced
accepted policies, so the number it reported said nothing about the generator
being pinned.

The generator now builds a valid policy and perturbs one slot (sometimes two)
from a pool covering every optional field, and the guard runs on that same
generator: 1417 of 4000 accepted, against a floor of 1000. Reverting any of the
four fixes above now fails it; before the rewrite, reverting the `rule.metadata`
fix did not.

### Vue's access state shared the permission map the caller still held

`createAccessState(map)` put the caller's object straight into its `ref`, and
`update(next)` assigned `next` itself. React's `AccessProvider` and the vanilla
`IamAccessClient` both copy the map in and both say why in a comment;
`createIamPermissionChecker` shares it deliberately and documents that. Vue was
the one surface that shared it silently — and it shared in both directions,
since the `Ref` also hands the stored object back through `permissions.value`.

So on Vue, and only on Vue, `map['delete:post'] = true` after construction made
`can('delete', 'post')` start answering `true`, with no reactivity triggered:
`ref()` sees an assignment to `.value`, not an edit inside the object it holds.
The same write through `state.permissions.value` did the same thing. The map is
client-side and the server re-checks, so this is a UI-correctness and
cross-binding-consistency bug rather than a bypass — a gate rendered from a map
somebody else could edit.

`createAccessState` now stores `Object.freeze({ ...map })`, in the constructor
and in `update`, which closes both directions: the copy defends the map you
handed in, the freeze defends the one you read back.

The reference doc's ownership matrix was wrong in two more cells while it was
there: it said a write into the map React's `AccessProvider` hands back changes
`can()`, but that snapshot has been frozen all along. All four surfaces are now
pinned by one table-shaped test rather than by prose.

### A Next route handler's own error was reported as an authorization failure

`withIamAccess` wrapped the route handler in the same `try` as the permission
check, so anything the route threw came back through the adapter's `onError` —
documented as *"handles thrown errors during evaluation"* — and the client got
the IAM layer's 500 `{error:'Internal server error'}` instead of whatever the
route meant to answer. Next's own error handling never saw it.

Only half the time, which is the part worth knowing. The call was spelled
`return handler(req, ctx)`, with no `await`, and an unawaited `return` inside a
`try` still routes a *synchronous* throw to the `catch` while letting a
rejection past. So the same route error behaved differently depending on
whether the route was declared `async`.

Hono had this fixed a round earlier, and it was written up then as hono being
"the only one of the five". That was wrong: the check behind it looked for an
*awaited* downstream call inside the try, and `withIamAccess` was not awaiting.

`handler(req, ctx)` now sits outside the try, as `await next()` does in hono.
`cross-adapter.test.ts` runs the assertion against both spellings, and a new
express control in the HTTP e2e boots a real express app to show why the one
adapter still calling its downstream inside the try is unaffected: express
dispatches each layer inside a try of its own and turns the throw into
`next(err)` before it could unwind.

### A malformed role grant in the file store turned a deny into an allow

The file adapter's assignment parser dropped a malformed `{role, scope?}`
entry, reported it through `onPolicyError`, and answered the read with the
grants that did parse. Losing a grant reads like *less* authority, so this
looked safe. It is not: a policy's `targets.roles` names the subject's
**grants**, and `policyApplies` drops a policy whose targets no longer
intersect the subject's roles. A deny policy targeting `banned` stops applying
the moment the `banned` grant cannot be read, and the allow that the same file
grants through another role carries the decision.

Measured through the engine, with an `allow-all-read` policy and a
`deny-banned` policy targeting `targets.roles: ['banned']`: a subject holding
`reader` + `banned` is denied; the same subject whose `banned` entry is
`{role: 'banned', scope: 5}` — a number where a string belongs — is **allowed**.
Same for `{role: 42}`, for a bare string entry, and for a row that is not an
array at all.

The same file already fails closed for a corrupt *attributes* row, for the same
stated reason, so the fix is that design applied to assignments: the row moves
into `corruptAssignments`, `getSubjectRoles` and `getSubjectScopedRoles` throw,
and `assignRole` / `revokeRole` / `updateAssignmentScope` refuse — an
incremental edit would write back a row with the unreadable entry silently
gone.

The second half was worse than the read. `_serializableState` wrote the
*parsed* assignments back, so the next flush of any kind — an unrelated grant
for another subject — erased the malformed entry from disk permanently, and the
store then looked clean. The raw row is now written back verbatim, as the
corrupt attributes row already was, so the file still holds what an operator
has to repair. `deleteRole` cannot sweep a row it refuses to read, and now
reports each one it skipped rather than implying the role is gone.
