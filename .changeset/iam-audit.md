---
'@gentleduck/iam': minor
---

Authorization-correctness audit: behaviour fixes across evaluation, writes,
availability, the client adapters and the public type surface, plus the test,
packaging and documentation defects that had been hiding them.

### Production allowed what development denied

The compiled table produces the verdict in *both* modes, so a disagreement with
the interpreter ships before the development cross-check ever sees it. Five such
divergences:

- An unrecognised `rule.effect` fell into `evaluatePolicyFast`'s else-branch and
  read as an allow, so a policy whose only rule was a deny answered ALLOW. Both
  branches now test the effect by name.
- `conditionMayThrow` under-approximated: an absent `value` on a non-valueless
  operator, an `OPERAND_TYPES` mismatch on a `$`-resolved operand, and a
  non-array `all`/`any`/`none` body each let the fast path return an allow
  without reaching the deny rule that would have thrown.
- A duplicate role id made `compileTable` build groups no subject can hold
  (`roleMask === 0`); `rbacVote` counted them as real grants and cast a phantom
  `defaultEffect` vote — a fail-open under `defaultEffect: 'allow'`.
- `eq`/`neq` compared `null === null` when a `$`-reference resolved to nothing,
  so `subject.attributes.tenant eq $resource.attributes.tenant` allowed a request
  carrying neither attribute. A `$`-reference with no value is now Indeterminate;
  a literal `value: null` still compares.
- `not_contains` returned `true` for any array or object operand, so an "allow
  unless denylisted" rule admitted everyone. `contains`/`not_contains` now take a
  `scalar` operand in `OPERAND_TYPES`, closing the read and write paths from one
  table — the fix `nin` already had.
- A condition group the evaluator could not evaluate — nested past
  `MAX_CONDITION_DEPTH`, or carrying keys it does not recognise such as a typo'd
  `all` — answered `false`. That is fail-closed only for an *allow* rule; on a
  deny rule it retires the deny, and inside a `none` the negation turns it into a
  grant. Both sites now raise `IamConditionGroupError`, making the policy
  Indeterminate so a deny-bearing policy votes deny. `conditionMayThrow` and
  `explain`'s trace were widened to match, so the fast path and the trace cannot
  answer a group the interpreter refuses.
- `eq`/`neq` are `f === v`, so a non-scalar operand compared by reference against
  a value resolved out of the request and could never match: `eq` was permanently
  false, `neq` permanently true. Neither was listed in `OPERAND_TYPES`, so a deny
  rule written `tenant eq { ... }` validated clean, saved through the fully
  validated `admin.savePolicy`, and then allowed the subject it was written to
  block. `operandHasType('array')` checked only the container, so `in` and
  `superset_of` passed an array of objects the same way. Both are now `scalar`,
  and `'array'` requires scalar elements.

`matches` answered `false` for the three patterns it refuses to compile — one
resolved from a `$`-reference, one over the length cap, and one the
catastrophic-backtracking detector or the regex parser rejects. `false` reads as
"condition not met", which is fail-closed only for an `allow` rule: on a `deny`
rule it retires the deny, and inside a `none` the negation makes it a grant. Two
of the three were measured through `engine.can` as over-grants — a rule denying
a banned email by a pattern held on the resource, and one blocking a user agent
by a pattern the detector refuses, each allowing exactly what it named, with
nothing reported. All three now throw, so the condition is Indeterminate and a
deny-bearing policy votes deny. The same reasoning already governed the *input*
side of that operator and had never been carried across to the pattern side.

`ops.matches` was a second hand-written copy of `evalMatchesOp`, so a rule about
when the operator refuses could hold on one path and not the other. It now
delegates.

### Writes that invented grants

`admin.updateAssignmentScope` conflated two answers: `updateAssignmentScope`
returning `false` means "there is no such grant", while the method being *absent*
means "I cannot do this in place". Both fell through to the same revoke + assign,
so a move naming a grant that was not there wrote one at the destination scope
and emitted `role.scope-changed` announcing it. A mistyped `fromScope` was a way
to hand out a role, on all six backends. Both paths now return without writing
when no row matches, and the event fires only when one moved.
`admin.moveRoleScopes` inherits the fix.

`'*'` is refused as an assignment scope on the write path; lookups still treat it
as global.

The file adapter answered with grants the store had refused. Every write mutates
its in-memory copy and then flushes, and a rejected flush left the mutation
behind: `assignRole` rejected with the driver's `ENOSPC` and the same adapter
went on reporting the subject as holding the role, so `can()` allowed an
authorization the operator was told had not happened. Because a flush serialises
the whole copy, the next successful write of any kind — an unrelated
`assignRole` for another subject — then committed the refused grant to disk. The
adapter now discards its in-memory copy when a flush fails and reloads from the
file on the next read, so a refused write leaves no trace. A write queued behind
a failed one is refused rather than handed the failed state.

A batch write that failed part-way left the engine serving the rows it had
already written. `assignRoles` and `revokeRoles` fall back to a per-row loop on
any adapter without set-based writes, and a throw skipped both the cache
invalidation and the mutation events — so a revoke that landed in the store kept
answering allow until the TTL, with no `role.revoked` for an audit log to record
or another node to act on. Both now invalidate every subject the batch named
before rethrowing, and announce the rows known to have landed.
`updateAssignmentScope`'s revoke-plus-assign fallback does the same when the
re-grant fails.

The redis adapter turned its documented shallow merge into a full replace
whenever the read that feeds the merge failed. The catch was written for one
case — an existing blob too corrupt to parse, which an operator must be able to
overwrite rather than be locked out by — and it also swallowed *the read never
happened*, continuing with an empty bag. A transient driver error during an
unrelated attribute write therefore destroyed every attribute already held,
including deny attributes such as `suspended`, and the call reported success so
nothing retried. The corruption case is now a tagged error and is the only one
tolerated; a failed read fails the write.

The prisma and drizzle adapters had the same catch. Both now read the bag
without catching, so a failed read rejects the write and leaves the stored bag
untouched. Only a bag that exists but cannot be read as one is still
overwritten: prisma warns, drizzle reports through `onPolicyError`. The errors
thrown are unchanged.

`getSubjectAttributes` handed the caller a live handle on the store on two
adapters. The file adapter returned the object out of its cached state, so a
caller's edit survived a re-read and was serialised to disk by the next
successful write — a write for an unrelated subject. The memory adapter copied
the bag with a spread, which aliases every array inside it, so pushing onto a
returned `groups` array reached the store; membership attributes are the ones
policies read. Both now copy one level deep, which is exactly as deep as an
attribute value goes. The comment that had claimed the other adapters could not
do this named the file adapter among them, and was wrong about it.

The same boundary was open in the other direction, and closing only the read
side had moved the alias rather than removed it. `setSubjectAttributes` merged
the caller's patch shallowly on both in-memory adapters, and the memory
constructor's seed copied the same way, so an array inside the patch stayed
shared with stored state: pushing onto it added a membership value *after* the
write had returned, with no second write to validate it and nothing to
invalidate a cache from. Both adapters now copy the patch as well as the result,
to the same depth.

Save-time validation only holds if the store stops sharing rows with the caller.
The memory and file adapters kept the object they were handed: the policy
normaliser rebuilt the policy but carried `rules` across by reference,
`saveRole` stored the argument itself, and both served their stored objects back
on every read. Pushing a rule onto a policy after `savePolicy` had returned — a
rule the save-time check never saw, granting `delete` on `*` — changed what the
adapter answered, and on the file adapter the next unrelated write serialised it
to disk. Every other adapter serialises on the way in, so the same program
behaved differently depending on which one was configured. Rows are now cloned
on save, on seed and on read, which is the invariant attribute bags already had.

A transaction-bound facade buffers its cache invalidations until the caller
commits, but the engine it exposes for reads carried its own `admin`. A write
made through `bound.engine.admin` went through the transaction and then
invalidated only the transaction-local caches, so a committed revoke left every
node — this one included — answering `true` until the TTL expired, while
`onMutation` announced the revoke before the commit that might never come. The
facade now exposes one write surface however it is reached.

### Availability and denial of service

- `policyCombine: 'first-applicable'` was folded as `'and'` by `lookup()`, so
  every affected request answered `Evaluation error`. It now routes to the
  interpreter, which implements it.
- One throwing role permission poisoned every unrelated grant in its RBAC cell.
  The compiled path now abstains per grant, matching the interpreter's documented
  `rulesAbstainOnThrow`.
- `invalidateRoles(roleId)` could not reach in-flight subject loads, so a role
  revoked mid-load was re-cached with a full TTL.
- `detectCatastrophicRegex` accepted `^.*/.*/.*/.*\.json$` — an ordinary glob —
  which backtracks O(n^4): 2 s at 384 characters against a 2048-character input
  cap, driven by a request attribute. Unbounded quantifiers separated by
  characters they can themselves match are now detected as one run. Patterns
  whose separators confine them, such as `[a-z]+@[a-z]+\.[a-z]+`, are unaffected.
- The role-limit latch that disables the compiled table above 32 roles was never
  cleared. Verdicts stay correct because the interpreter answers, but the table
  was lost for the life of the process and `healthCheck()` went on reporting
  `role-limit-exceeded` with the role count from the moment it tripped — so an
  operator who deleted roles in response to the alert watched the alert not
  clear. It is now cleared whenever the role set can have changed, including on
  cross-instance invalidation events so replicas recover too, and the
  warned-once flag resets with it so a second excursion is reported.
- The Redis invalidator's signed pre-image omitted the channel, so an envelope
  signed for one tenant verified on every other tenant sharing the secret — and
  the secret is a deployment-wide value while `tenantId` is what namespaces the
  channel. A party who can SUBSCRIBE to one channel and PUBLISH to another
  injected authentic-looking invalidations without holding the secret; the event
  vocabulary is drop-only, so the cost is forced cache wipes and re-reads, not a
  grant. The channel is now part of what is signed (wire version 2) and an
  envelope whose signed channel is not the channel it arrived on is dropped.
  During a rolling upgrade, set `acceptLegacyUnboundEnvelopes: true` to keep
  accepting pre-v2 envelopes — it reopens the cross-tenant relay, warns once per
  channel while it is on, and should be turned off once every node publishes v2.
  Dropping invalidations is the worse failure: a cache goes on honouring a
  revoked grant until its TTL.
- A signed envelope verified for the full ±30 s window however many times it
  arrived, so anyone with PUBLISH rights on the channel could capture one real
  envelope and repeat it: cache wipes on demand for the rest of the window,
  without ever holding the secret. Each node now remembers the signatures it has
  applied and drops a second copy, naming it (`replayed envelope (this signature
  was already applied)`). The set is per node, holds at most 5 000 signatures,
  and exists only when a `secret` is configured — an unsigned channel has
  nothing authentic to dedupe. One consequence: a node that publishes the same
  event twice inside the same millisecond emits one envelope twice and peers
  apply it once, which is the same cache wipe either way.
- Every hook that returns a promise was awaited without a bound, so a
  `beforeEvaluate`, `afterEvaluate`, `onDeny` or `onError` whose promise never
  settled — an audit write to a stalled database — held `can`, `authorize`,
  `permissions` and `explain` open indefinitely, and `onMutation` did the same
  to admin writes. With the adapter down, fail-closed became no answer at all.
  The new `hookTimeoutMs` (default `5_000`, `0` waits indefinitely) bounds each
  wait: a `beforeEvaluate` that times out fails the evaluation through `onError`
  and denies; every other hook is logged and left running while the call
  returns. A hook that returns synchronously starts no timer.

- The same unbounded wait survived on the transaction path: a bound facade
  handed `onMutation` to its pending buffer raw, so `pending.flush()` — which
  runs *after* the caller's transaction has committed — waited on it forever
  whatever `hookTimeoutMs` said. It goes through the same bounded call now, and
  the default lives in one constant both paths read.

### Decisions that were silent

The prisma adapter's role read path dropped a row failing `validateRole` without
a word — `listRoles` omitted it and `getRole` returned `null`, the same answer a
role that never existed gets. It now warns with the validator's own issue
messages and skips the row, matching `_readPolicy` beside it.

`isResolvablePath` claimed to stay in lock-step with the resolver but shared only
`ALLOWED_ROOTS`, not `BLOCKED_SEGMENTS`, so a condition on `subject.__proto__.x`
validated clean even though `resolve` answers `null` — an inert deny rule drew no
warning. `BLOCKED_SEGMENTS` is now exported and shared by both callers. It stays
a warning: the rule was already inert, so no stored policy changes meaning.

Four of the package's five tagged error classes were exported from no barrel,
though each is documented as carried for `instanceof` routing through
`onPolicyError` — leaving `err.name` string comparison as a consumer's only
handle. All five are now exported from the conditions, core and root barrels,
and the test that guarantees this derives its list from the source instead of
naming a single class, which is why it had not noticed the three added after it
was written.

`validateRoles` accepts the unconstrained role type on purpose — it exists for
rows out of an adapter, a config file or an admin form — and then dereferenced
`id`, `permissions` and `inherits` without checking any of them, so exactly that
input threw a `TypeError` instead of being reported. A caller asking "is this
data safe to load?" received an exception that reads as a defect in the package
rather than an answer about their data. A string `inherits` did not even throw:
it was walked character by character and reported one dangling parent per letter.
Malformed entries are now returned as `INVALID_TYPE` issues and the pass
continues over the rows beside them.

The refusal message for a `matches` pattern read out of request data told the
policy author the opposite of what happens. It said the condition "would always
be false and the rule would never fire"; evaluation raises instead, which makes
the policy indeterminate, and an indeterminate policy still votes — deny if it
carries any deny rule. An author who read that message as "this rule is inert"
was being told to ignore a rule that may have been denying every request that
reached it.

A replica whose Redis `subscribe` failed at boot — `NOAUTH`, a wrong ACL, a
broker down for the seconds the pod took to start — never received another
invalidation, and nothing about it was visible. `healthCheck()` round-trips the
adapter and builds the compiled table; both still work on such a node, because
the database is not what broke, so the probe reported `ok: true` with no field
naming the invalidator at all. The node answered from its own caches and served
pre-revocation decisions for up to one `cacheTTL` past somebody's write, with no
symptom an orchestrator or a dashboard could see.

`IInvalidator` gains an optional `status?()`, and `IHealth` an optional
`invalidator` field, present only when that status reports the subscription is
not live — the same shape as the existing `compiledTable` field, so presence
alone is the alert condition. `ok` deliberately stays `true`: the causes are
fleet-wide correlated, a rotated credential or an unreachable broker hits every
replica at once, and failing the probe would pull the whole fleet and turn
bounded staleness into a total outage. `status` is optional so an invalidator
written against the previous two-method contract still compiles, and it is
narrowed rather than trusted — a `status` that throws or returns the wrong shape
is reported as no claim and warned about once, never propagated, because an
optional accessory must not take out the route that says whether the adapter is
reachable.

The Redis invalidator now also retries. Its only retry path was a second
`subscribe()` call, which an engine never makes — `setInvalidator` subscribes
once — so for every real caller a boot-time failure was permanent, while the
operator warning and the `onSubscribeError` docblock both promised that a later
`subscribe()` would recover it. A `publish` now re-attempts, at most once every
five seconds, and both strings were rewritten to describe what actually happens
including what still does not: a node that only reads calls neither, so it never
retries. The retry never *initiates* a subscription — an invalidator used
publish-only has deliberately not subscribed, and a Redis client that subscribes
enters subscriber mode, where `publish` itself stops working.

`permissions()` never called `afterEvaluate` or `onDeny` in production. Its hook
block required the decision object only development builds, while `can()` and
`authorize()` synthesise a verdict-only decision for the hooks — so a denial log
wired to them recorded every single check and no batch check, in the mode
deployments run. `permissions()` now hands the hooks the decision `can()` does,
once per check, with or without `telemetry`.

### Types that did not describe the runtime

Several declarations were wrong in a way callers had to work around, so the cast
at the call site was the type's fault rather than the caller's.

Every server adapter's `IAdminAuthorize` was typed `=> boolean`, while
`iamRunAdminAuthz` forwards a truthy non-boolean return on as the **actor** and
the adapters' own docs instruct operators to return one so the audit log names a
human. Following the docs required a cast; following the type lost attribution.
The answer is now a named type, `IamAdminAuthzAnswer`, exported from the generic
entry point and used by express, next, hono and nest. `number` is deliberately
outside it: a numeric id is not forwarded as an actor, and the type now says so.

The same audit event's `targetId` is declared `string`, and on express it was
not one. `PUT /policies` and `PUT /roles` carry the document id in the body, and
the event is built before the validator runs — a refused write is exactly what
an audit trail is for — so the id is read out of whatever JSON arrived. Hono,
next and nest read it through a checked helper that answers `undefined` unless
the id is a non-empty string; express cast the body and recorded the field
verbatim, so `42`, `true`, `null`, an array or an object each landed in a field
consumers type as a string. The write was refused either way, so no policy was
ever authored this way, but an audit sink formatting that field or writing it to
a string column was being handed arbitrary structure by a rejected request.
Express now uses the same helper as the other three.

In the express and hono middleware options, `getScope` was typed at the caller's
scope union while `getAction` and `getResource` beside it took plain `string` —
so a typo in an action or resource name type-checked. `IOptions` gains `TAction`
and `TResource`, appended after the existing `TScope` so no existing
instantiation changes meaning, and a `NoInfer` on the options parameter makes a
typo blame the callback that is wrong instead of the engine argument.

Eleven types used in exported signatures — express's `Req`, `Res`, `Next`,
`Middleware` and `ExpressRouterLike`, hono's `HonoContext`, `HonoMiddleware` and
`HonoNext`, `NestExecutionContext`, and next's `RouteHandler` and `RouteContext`
— were never exported themselves. Re-exporting a configured middleware from your
own module raised TS4023 with no annotation available to silence it, because the
name TypeScript asked for was not public. All are exported now, and the
nameability sweep covers the server adapters rather than only the core types.

### Client-side checks that disagreed with the answer they were given

A client check is advisory, so none of these is an authorization hole — but each
makes the UI assert a grant the subject may not hold, which is the whole job of
the layer.

The React client's shared empty-permissions object was one unfrozen instance per
factory, held by every hook while it loaded, so a consumer writing an optimistic
entry wrote into the object every other loading hook was holding. It is frozen
now.

`refetch()` ran the closure captured on the first render. `load` is memoised on
`deps`, which by contract exclude `fetchFn`, so a `fetchFn` closing over a
subject id re-fetched the previous subject after an account switch — and the
hook's own documentation offered `refetch` as the fix for exactly that
situation. The latest closure now lives in the box `load` already reads, so
`deps` still decides when a fetch happens and `refetch` uses what the caller
currently has.

`AccessProvider` read the caller's permission map by reference and memoised on
its identity, so mutating the map changed what `can()` answered while nothing
re-rendered — the predicate and the rendered UI disagreeing with no way to
notice. Copying it closed one direction and left the mirror open: the context
exposed that copy as `permissions`, and it is the object `can()` reads, so
writing into what the hook handed back reached the predicate just the same. The
snapshot is now frozen — rather than re-copied per read, because consumers put
`permissions` in dependency arrays and a fresh identity there loops — so the
write does not apply. The vanilla client has always guarded both directions and
explains why in its own docblock; React now matches it. The standalone
`createIamPermissionChecker` still returns the caller's own object, which is a
predicate over a map the caller already owns rather than state shared across a
tree.

`IamAccessClient.fromServer` built its headers by spreading `init.headers` into
an object literal. `RequestInit` admits a `Headers` instance and a list of
`[name, value]` pairs, and spreading either yields nothing usable, so an
`Authorization` supplied in those two forms never reached the request — silently,
since the endpoint then answered for an anonymous caller or refused the call.
The headers are built through `Headers` now, with the JSON content type set only
when the caller did not set one.

### Adapter compliance runs every clause on every adapter

Nineteen clauses bowed out with `ctx.skip()` when an adapter lacked the optional
method they exercised — 84 skips across two tiers from one place. Three of the
six optional methods are optimisations the engine falls back for, so the
behaviour holds everywhere; those are now pinned for all six by a new
engine-level suite, `runEngineCapabilityCompliance`, which asserts through
`engine.admin` and has nothing to skip. The other two were already covered by
dedicated tests and their duplicate clauses were deleted. Clauses that genuinely
only apply to an implementation are registered from a declared support matrix
rather than by probing the instance, so a method that disappears turns a row red
instead of converting asserting tests into skipped ones.

Fourteen read-back assertions inside those clauses still asked the instance
(`if (a.getSubjectScopedRoles)`), so with the method absent the assertion
vanished rather than failed. They now gate on the declaration and throw when the
matrix claims support the instance does not have.

`runAdapterCompliance` now takes a required `supports` option. Third-party
adapters pass their own literal.

The drizzle adapter branches on `dialect` and ships three of them, but SQLite
had no behavioural coverage at all — only a static schema comparison and a type
check, so the claim that it upserts like Postgres rather than like MySQL rested
on reading the branch. It now runs against a real SQLite engine, which is the
only way to answer this honestly: a mock implements whichever call chain the
adapter makes and agrees with it. SQLite issues one atomic upsert as Postgres
does; MySQL, which has no target-scoped `ON CONFLICT`, reads first and then
branches, and two concurrent writes of the same new id there surface the
driver's duplicate-key error. The divergence is real, MySQL-only, and now
measured rather than asserted.

### Test doubles that certified the wrong contract

Both Prisma doubles — the unit mock and the real-Postgres e2e delegate —
discarded the `update` half of every upsert and wrote the `create` payload on
conflict. That is the inverse of the documented contract: `created_by` was
re-stamped on every edit and `updated_by` never written, and with `update`
dropped there was nothing to assert against, so Prisma had no provenance test at
all. Both doubles now apply `update` on conflict, and a provenance suite mirrors
the drizzle one.

The negative control for the subject-load-shed cap contained no assertion at all,
so a cap that shed unconditionally — denying every request in the deployment —
would have passed the one test written to prevent it.

Two adapters were certified in a configuration no deployment runs. The file
adapter's fake filesystem had no `rename` and the adapter no `rootDir`, so every
compliance clause took the in-place fallback and root containment returned
before looking at anything — with the warning that announces the degraded mode
silenced by a spy. Deleting the write entirely, so the adapter persisted
nothing, left all 107 clauses passing. The drizzle matrix ran the pg chain only,
while MySQL's upsert and insert-or-skip are separate implementations of the same
contract reached through a different builder; dropping the update half of the
MySQL upsert cost one failing test out of 261. Both now run the shipped
configuration, and MySQL runs the full matrix against a mock brought level with
the pg one — foreign key enforced, cascade on role delete, `isNull` and `or`
supplied, and reads awaitable at every shape the adapter uses.

The file adapter's `concurrent flushes are serialised` tests asserted on the
bytes left on disk, which cannot distinguish serialised from interleaved: the
flush serialises a live shared cache at flush time, so both racing payloads are
identical whatever order the renames land in. Removing the flush chain outright
left the block passing. They now assert the ordering that the invariant is
actually about.

`a failed write does not poison later writes` was passing for the opposite
reason to the one it named. It asserted the queued write *fulfilled*, and it did
— because the two writes share one live cache object, so the second flush wrote
the failed write's mutation to disk along with its own. The assertion it never
made was that the failed write is absent.

A test stripped an optional adapter method with `delete adapter.method` to
exercise the engine's fallback. The adapters implement these as class methods,
so `delete` on the instance removes nothing and still returns `true`: the test
named for the revoke-plus-assign fallback was running the in-place path, a
duplicate of the test above it. The fallback is covered elsewhere by adapters
that genuinely lack the method, so this was a misnamed duplicate rather than a
coverage hole. Capability stripping now goes through a helper that shadows the
prototype method, and carries the measurement that says why `delete` does not.

The Postgres transaction suite passed drizzle only `and` and `eq`, so it proved
the transactional behaviour of statements a deployment does not run: without
`or`, a bulk revoke degrades to one `DELETE` per row, and without `isNull` an
in-place scope update cannot match an unscoped grant and falls back to revoke
plus assign. It now runs the full operator bundle.

The prisma attribute test asserted the cause-blind overwrite as intended: a read
failing with `connection terminated`, then a stored bag holding only the call's
keys. It now asserts the write is refused and the bag untouched. The drizzle
actor-provenance mock could not answer the read `setSubjectAttributes` does
first; it threw a `TypeError`, and the attribute provenance test passed only
because the write swallowed its own read failure. The mock now answers it.

### Documentation that described the opposite of the code

Corrections throughout, plus the packaging gap that kept the shipped README's
links from resolving at all. The consequential ones:

- The compiled-engine doc showed the RBAC scope check as an exact-equality
  fence. It is `scopeCovers`, so under `scopeMode: 'hierarchical'` a grant at
  `org-1` covers the whole subtree — an operator reading it fences one org and
  grants the tree.
- The FAQ advised `iamFlushSharedCaches()` as a multi-tenancy mitigation.
  SECURITY.md, the function's own docblock and the code all deny it: it clears
  only process-global fallback caches that no `can()` path touches.
- `onPolicyError` docs on file, redis, http and drizzle claimed a malformed row
  is dropped and the rest returned. Only *role* rows are dropped; a malformed
  *policy* row throws and fails the whole read, because the dropped policy could
  be the one that denies. The prisma and drizzle class docblocks additionally
  credited a placeholder fallback that does not exist, prisma naming an
  `onPolicyError` it has no constructor parameter for.
- `_getCompiledTable`'s "`null` means exactly one thing" was contradicted
  fourteen lines below in its own body.
- The FAQ described `mode` as selecting `evaluate` vs `evaluateFast` (it selects
  neither), and described three rule-index particulars the code records as fixed
  production bugs.
- `prisma.getSubjectRoles` is documented as unscoped-only, matching what it
  filters; SECURITY.md's Nest default and `checkMany()` names are corrected.
- A comment justified dropping two operators from the transaction harness with a
  type constraint that had since been lifted. A stale justification is worse than
  none: it reads as a reason to leave the gap alone.
- `package.json` did not ship `docs`, so every `docs/` link in the shipped
  README — including the one introduced as "Reference (start here)" — was a dead
  path for anyone who installed the package rather than browsing the repository.
  The reference documentation is now published with it, and a test asks the
  packaging question rather than the filesystem one, which is why the suite had
  never noticed.
- `maxConcurrentSubjectLoads` was documented as unbounded by default. The default
  is 512 and `0` is the opt-out — it told an operator the load guard was off when
  it was on.
- The comment on role invalidation had the two halves backwards, describing the
  local cache sweep as wholesale and the published event as narrowed when the
  code does the reverse; read literally it made the targeted sweep beneath it
  look like dead code.
- `preload()` documented the compiled table as built in production mode only,
  contradicted nine lines below in its own body; the RBAC resolver credited a
  `visited` set that does not exist and cannot (the memo is what cuts a cycle);
  and drizzle's MySQL upsert justified its read-first path with unique
  constraints all three schemas deliberately removed. The divergence that path
  guards is real; the reason given for it was not.
- `circuitBreakerThreshold` was documented as disabled by setting it to `0`,
  which the constructor refuses — deliberately, because these values arrive from
  `Number(process.env.X)` and an unset variable would otherwise silently disable
  a protection. There is no disable switch; omit the option to take the default.
- Two docblocks were attached to the wrong declaration — one describing the
  production decision builder sat above a different method, which has its own
  docblock, leaving the method it described with none. A documentation generator
  misattributes that as readily as a reader does.
- A sweep of comments that narrate a past fix instead of describing current
  behaviour. These read as current-state description until you notice the tense,
  and two of this audit's own false leads came from them. The reasoning was kept
  in every case; where a comment records what the code used to do, it now says so
  under an explicit marker and leads with what the code does now.
- Two behaviours that were correct, tested and undocumented, which reads the same
  way to anyone hitting them: drizzle's MySQL dialect does not upsert atomically
  — it reads the row and branches, so two writers saving the same id can both
  read "absent" and the loser takes the driver's duplicate-key error, where
  Postgres and SQLite let both callers succeed — and the client's
  `allowedActions` / `hasAnyOn` filter on the resource alone, so an action
  granted only in another scope or only on another record is still listed while
  `can()` refuses it.
- The admin audit hook (`onAdminMutation`) was documented on the generic helper
  and all four framework adapters as fire-and-forget that can never block the
  response or leak timing to the caller. It is called inline before the
  response, and only its returned promise goes unawaited: synchronous work,
  including anything after an `await` on a settled value, runs before the
  response and adds to its time. The docblocks say so now, and a test pins both
  halves.
