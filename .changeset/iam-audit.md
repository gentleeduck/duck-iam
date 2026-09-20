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

### The HTTP adapter answered a subject read with the half of the list that parsed

The same defect as the file store above, at the adapter where the payload is
remote and least trusted. `parseHttpSubjectRoles` skipped any element that was
not a non-empty string and `parseHttpSubjectScopedRoles` skipped any element
whose `role` or `scope` was not one, both silently, and both returned the rest.
A test pinned that as correct on the premise that "roles are allow-only" — the
premise the file-store finding had already disproved.

Measured through the engine over a fake server, with a `deny delete:post`
policy at `targets.roles: ['contractor']` and a subject holding `editor` +
`contractor`: the well-formed list denies, and the same list with the
`contractor` entry arriving as `{role: 'contractor', scope: 'org-1'}` — the one
server mistake the endpoint contract explicitly warns about — **allows**, with
nothing reported. Same for `null`, `42` and `''` in that position. A payload
where *every* element is malformed already failed closed, because a subject with
no roles has no allow either; only the partial list flipped the verdict, which
is why it survived.

`adapters-runtime.md` had documented the throwing behaviour as the contract for
both methods for as long as the drop existed. The parsers now match it: the
element that will not parse fails the read, naming its index and its type but
never its value. A row carrying no `scope` on `/scoped-roles` throws too — the
two endpoints are disjoint by contract, so that row is the server mixing them
up rather than a global grant. A malformed *catalog* row from `GET /roles` is
still dropped and reported, because a policy left targeting it is now reported
in its own right; a dropped grant has no such witness.

### A subject's grant of a role nothing defines lost every role it inherited

The grant-side half of the target check above, and the case that one could not
see. `resolveEffectiveRoles` deliberately keeps a directly assigned role id that
no stored role defines, so the id still matches an ABAC rule naming it and the
grant looks intact. But there is no row to read `inherits` from, so every role
that id conferred is silently absent — and a deny targeting one of *those*
retires.

Measured through the engine with a `deny delete:post` policy at
`targets.roles: ['contractor']` and a subject holding `staff` + `editor`, where
`staff inherits contractor`: with the `staff` row present the subject is denied;
with the `staff` row missing from the catalogue the subject is **allowed**, and
nothing is reported — the policy's own target, `contractor`, is stored and
healthy, so the target check stays quiet. A subject holding `contractor`
directly is still denied, and one holding only `editor` is still allowed, which
is what makes the middle row a finding rather than an engine that denies.

Four adapters drop a malformed role row rather than refusing it, on the reasoning
that role permissions are allow-only and a role nobody can resolve grants
nothing. The first half is true and the second does not follow: the drop is
tolerable only because something reports the grants left pointing at nothing.
Now something does, de-duplicated per role id — the absent definition is what
needs repairing and every holder shares it. Both grant paths report, global and
scoped. It changes no verdict.

The premise had been written into five comments and a test-file header across
the adapters; those now say what is actually true.

### A misspelled action or resource target retired a policy in silence

The third carrier of the same defect. `targets.actions` and `targets.resources`
are matched against the request, so an entry naming an operation the policy's
own rules never mention admits nothing and the policy is skipped for every
request — the same retired deny as a `targets.roles` entry naming no stored
role, which is already reported.

Measured with a `deny delete:post` rule: `targets: {actions: ['delte']}` allows,
`{resources: ['psot']}` allows, and both are silent, while the identical typo in
`targets.roles` is reported. Spelled correctly, or with no targets at all, the
deny fires.

No catalogue is needed to see it. The engine is never handed the declared
vocabulary — that lives on `createIam` and reaches only its `validatePolicy`,
which callers invoke or do not — but a policy's own rules are the vocabulary
that matters: if no pattern in any rule could match a request the targets admit,
the policy cannot fire whatever the catalogue says. Pattern intersection follows
the matchers, so `*` intersects anything and a prefix form keeps its separator,
leaving `post:*` and `post.*` disjoint exactly as `matchesResource` treats them.
One live rule among dead ones keeps the policy reachable and quiet.

### A condition reading a misspelled path silently stopped its deny from firing

One level below the targets: a rule's condition `field`. `resolve` answers
`null` for a path whose root is not `subject`, `resource` or `environment`, and
for one carrying a prototype key at any segment — on every request, for every
input. The rule then never matches, and the deny never fires.

Measured with a deny given a companion allow in the same policy, so the verdict
distinguishes a deny that fired from one that did not:
`subject.attributes.banned` denies, `resource.attributes.sensitive` denies, the
same subject unbanned is allowed — and `user.banned`,
`Subject.attributes.banned`, `subject.__proto__.banned` are all **allowed**,
with nothing reported.

The oracle already existed. `isResolvablePath` is exported for the validator and
kept in parity with `resolve` by its own test; it had no caller on the load
path, because `validatePolicy` is something users invoke and the engine does
not. The engine now runs it over every rule's conditions when policies load,
reporting once per policy, rule and path.

Deliberately not reported: a path that is merely *absent*, such as
`subject.attributes.bannd`. Its root is legal and its shape resolvable — whether
the key exists is a fact about the request, and attributes are open-ended. Also
not reported: a `$`-prefixed value operand, which `evalCondition` already
reports and answers Indeterminate rather than false.

### A rule its own policy's targets excluded could never fire, and the policy looked fine

The mirror of the dead-target check above. Reporting only when *no* rule matches
the targets left the harder case: the policy is reachable, one rule inside it is
not. The policy fires, so nothing looks wrong — and the deny in the excluded
rule is gone, better hidden than one in a policy that never applies.

Measured with an allow and a deny in the same policy under
`targets: {actions: ['delete']}`: the deny spelled `delete` denies, the deny
spelled `delte` **allows**, and nothing was reported either way, because the
allow rule kept the policy reachable. Same by resource.

Each excluded rule is now reported on its own, once per policy, rule and
dimension. A policy whose rules are all excluded is still reported once at the
policy level rather than once per rule. A wildcard target admits everything, and
a policy with no targets has nothing to judge its rules against, so both stay
quiet.

**The test that had to change.** The dead-target work had pinned "one live rule
among dead ones keeps the policy reachable" with `reported: []`. That was the
conservative choice at the time and this round measured it wrong: the policy is
reachable, and the dead rule still needs naming. It now asserts the policy-level
silence *and* the new per-rule report.

### An invalidation the engine cannot apply now drops the caches instead of being ignored

Events arrive from a transport the operator writes, so the engine now
shape-checks what it receives rather than trusting the handler parameter's type:
`kind` must be one of the four, a `subject` event must carry a non-empty string
`subjectId`, and a `roles` event may carry a non-empty string `roleId` or none.

Anything that fails that check is applied as `{kind:'all'}` - every local cache
and the compiled table dropped - and warned about once per distinct reason.
Before, an unrecognised `kind` was silently ignored, so a newer peer's event
during a rolling deploy left older instances serving the answer that peer had
just said was stale; and an event that was not an object threw out of the
handler, which on an EventEmitter transport is an uncaught exception. A value
that cannot even be inspected, such as a throwing getter or a revoked proxy, is
now a reason rather than a throw.

Note the trade: a transport that delivers malformed messages repeatedly will now
drop the caches repeatedly where before it did nothing. The warning names the
reason. There is no fleet amplification - every applied branch is local only.

The shipped redis invalidator already validated each decoded event and never
reached this path.

### An invalidator whose `publish` fails can no longer take the process down

`IInvalidator.publish` is operator-supplied code, is allowed to return a
promise, and runs on the revocation path. The engine called it as a bare
`void publish(...)`, so a rejection was unhandled - fatal under Node's default
`--unhandled-rejections=throw` - and a synchronous throw came back out of
`admin.revokeRole` as a failure, for a revoke that had already landed and
already cleared the local caches.

Both are now caught, as every other advisory callback in the engine already was,
and reported as one `console.warn` naming the event kind and stating that this
instance is up to date while other instances keep their caches until their own
TTL expires. No verdict changes, and the local caches are cleared before the
publish either way, so a transport failure degrades to per-instance TTL
staleness rather than to a local one.

The shipped redis invalidator already absorbed and reported its own publish
failures, so it never reached this path.

### A write that timed out no longer leaves the old answer cached

`adapterTimeoutMs` bounds how long the caller waits, not how long the store
takes, and an admin write takes `IActorOptions`, which carries no abort signal.
So a write that times out may well land a moment later. Until now the
invalidation that follows the write was skipped in that case, and the engine
kept serving the old answer for a full cache TTL: `revokeRole` could time out,
the row could be deleted in the store, and `can()` would still return `true`.

Every single-row admin write — `savePolicy`, `deletePolicy`, `saveRole`,
`deleteRole`, `assignRole`, `revokeRole` and both paths of
`updateAssignmentScope` — now invalidates whether the call resolves or throws.
Dropping a cache entry for a write that did not land costs one re-read; keeping
one for a write that did land is a revocation that never took effect. The batch
methods already worked this way.

`hooks.onMutation` is deliberately unchanged: it still fires only after a write
resolves, because an audit seam that records writes which may not have happened
is worse than one that misses a write whose outcome was never learned.

### A rule that no request can reach is now reported

A rule can be unreachable for reasons wholly inside itself, and until now
nothing said so. An empty `actions` or `resources` list matches nothing. An
empty `any` group is false for every request - while an empty `all`, an empty
`none` and `{}` are all true, so the one spelling that reads like "no
conditions" is the one that retires the rule. `in` against an empty list can
hold for no value. And a `none` group holding an item true for every request is
false for every request.

In each case a deny written that way never fires and the policy around it looks
healthy. The engine now reports each unreachable rule once through
`hooks.onPolicyError`, or one `console.warn` when no hook is installed. No
verdict changes.

Only falsity that reaches the rule is reported: the walk descends `all` chains
and stops under `any`, where a false item is a dead disjunct, and under `none`,
where a false item helps the rule apply. `subset_of` and `superset_of` against
an empty list are left alone because an empty array field satisfies them - a
fact about the request, not the policy.

`validatePolicy` already rejected the empty lists, but nothing on the load path
calls it, so a seeded row or a migration carried them straight past; the two
condition shapes were unguarded even at write time. Relatedly, a rule with an
empty list inside a policy that has `targets` was previously reported as one
the policy's targets exclude. That was a misdiagnosis - the rule is dead
whatever the targets say - and it now reports the rule's own list instead.

### A deny written against `scope` does not follow the hierarchy its grant does

Reported and documented, not changed — the behaviour is each operator doing
exactly what it says.

In `'hierarchical'` mode a grant at `org-1` reaches `org-1.team-a`, because
`rolesToPolicy` emits `any: [eq 'org-1', starts_with 'org-1.']` for it. A rule
an operator writes gets no such help: `scope` is an ordinary field and there is
no `scope_under` operator, so each obvious spelling of "this scope and below" is
wrong in a different direction, and two fail *open*.

Measured with an allow and a deny in one policy, subject granted at `org-1`:
`eq 'org-1'` denies the parent and **allows** `org-1.team-a`; `starts_with
'org-1.'` denies the child and **allows** the parent itself; bare `starts_with
'org-1'` denies both but also reaches `org-10`, a different organisation. Only
the two-arm form is right, and it is the one the package already generates
internally.

`core-rbac.md` now states this where the generated condition is shown, with the
table of all four spellings, and `scope-deny-follows-no-hierarchy.test.ts` pins
them in both modes so it cannot drift. Whether to add a `scope_under` operator
is a public-surface decision and is on the open-findings ledger.

### A recreated role id handed its permissions to everyone who inherited the old one

`deleteRole` removes the role and, on every adapter, the grants that named it —
with the reason written into the compliance suite: *"an orphan grant would be
held again if a role were recreated under the same id."* An `inherits` edge is
the other place a role id is written down, and nothing swept it. `iam_roles`
stores `inherits` as a JSON array, so the SQL foreign key that cascades the
grants cannot reach it either.

Measured on the memory and file stores: `u1` holds `reader` and `staff`, and
`staff` has `inherits: ['ghost']` where `ghost` grants `write:post`.
`deleteRole('ghost')` correctly takes the write away, but `staff.inherits` still
reads `['ghost']`. An operator then recreates `ghost` for something unrelated,
granting `delete:post` — and `u1` can delete, a permission nobody granted them.
`resolveEffectiveRoles` walks the surviving edge into the new role.

The interim protection was `resolveEffectiveRoles` dropping an inherited id no
role defines, which stops the *phantom-allow* half. It reads in one direction
only: a role id in `subject.roles` is also a selector — `policy.targets.roles`
matches it — so cutting the id retires the deny that was targeting it. Measured
on the same store: a subject reaching `banned` through `staff inherits banned`
is denied while `banned` is defined and **allowed** once its row is not. Both
directions escalate, so the state must not arise in the first place.

`deleteRole` now strips the edges as well as the grants, on all six adapters
(the HTTP adapter's reference server included), and the compliance suite pins
both the edge sweep and the end-to-end escalation, so a new adapter cannot miss
it.

### The one write path the scope guard did not cover

`iamAssertAssignableScope` is the adapter-boundary guard that refuses two scope
values: `''`, because the redis adapter spells "no scope" as `''` and would
store it as a global grant, and `'*'` on a grant, because a scoped assignment is
matched *literally* — a `'*'` row answers only a request whose own scope is the
string `"*"`.

`assignRole` and `revokeRole` called it. So did drizzle's `assignRoleMany` and
`revokeRoleMany`. `updateAssignmentScope` — the third method that takes a scope
to write, and the only one that takes two — called it on neither end, on all
four adapters that implement it. Its own doc comment listed the two methods it
covered, which is why it read as complete.

Measured on memory, file, prisma and drizzle:
`updateAssignmentScope('u1', 'editor', 'org-1', '')` and the same with `'*'`
both returned `true` and left the subject holding `editor` under a scope no
request can name. The operator is told the grant moved; it is dead.

Both ends are now guarded — the `from` as a lookup, so a legacy `'*'` row can
still be moved off, the `to` as a grant — and two compliance clauses hold every
adapter to it.

### The subject entry outlived the role snapshot it was resolved against

`IamLRUCache.set` takes a `notAfter` so a derived entry expires with its input,
and three call sites use it: the RBAC policy expires with the role snapshot, the
merged policies with the older of their two inputs, and the compiled table
stamps itself with the read time of its oldest input rather than `Date.now()`.

The subject entry is the fourth derived value and was not capped that way. It
holds `resolveEffectiveRoles(assigned, snapshot)` and, for scoped grants, roles
resolved through `inherits` against the same snapshot, so both halves are only
as fresh as the role graph they were resolved against. The one cap it did take,
the optional `getSubjectGrantBoundary`, describes the subject's *assignment*
rows and says nothing about the role graph.

Because each subject is written at its own moment, one resolved late in the
snapshot's life bought a full fresh TTL past it. Measured at the default
`cacheTTL: 60`, with the `staff -> admin` inherits edge removed at the store by
another writer: a subject resolved at t=50s still held `delete:post` at t=61s,
after the engine had re-read the role graph without that edge and was already
answering deny for every subject resolved since; it converged only at t=110s.
The exposure is up to one whole `cacheTTL` beyond the point the engine itself
knows the role changed, and it needs no adapter feature to reach - any engine
whose roles are written by something other than its own `admin` facet is in it.

The entry is now capped at `min(grantBoundary, roleCache.expiresAt('all'))`,
which costs nothing when the snapshot is fresh because the two are then the same
instant.

### A policy targeting a role nothing defines was skipped in silence

`policyApplies` matches `targets.roles` by equality against the request's
effective roles and against nothing else; there is no catalogue lookup. An entry
naming a role no stored row defines therefore matches no subject, and the whole
policy is skipped on every request. A typo is enough.

For a deny policy that is a deny that never fires, which is the one outcome this
engine otherwise refuses to be quiet about - a policy that cannot be read throws
rather than being dropped, a condition that cannot be answered is Indeterminate
rather than `false`, a policy that throws still votes deny. Measured with every
diagnostic hook attached: a `deny delete:post` policy targeted at `contarctor`
instead of `contractor` let the subject delete, in both modes, with
`onPolicyError` and `onError` silent.

The second way in is `deleteRole`. It sweeps the grants and the `inherits` edges
that named the role, but it cannot sweep this carrier, and the asymmetry is not
an oversight: `targets.roles: []` means *unconstrained*, so stripping the last
entry would widen the policy from one role to every subject rather than narrow
it to none. There is nothing safe to rewrite and nothing to decide at evaluation
time, since the state is indistinguishable from a policy written before its
role.

So the engine reports it instead: one `onPolicyError` per `(policyId, roleId)`
for the engine's lifetime, or one `console.warn` when no hook is installed. Both
evaluator paths carry the check - the compiled-table build and the interpreter's
`loadAllPolicies` - because either can be the only one that runs, and the
de-duplication is what keeps development mode, where both run, from reporting
twice. It costs no extra adapter read and changes no verdict.
