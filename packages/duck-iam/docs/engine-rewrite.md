# Rewriting the duck-iam engine: compile the model

Keep the RBAC and ABAC model exactly as it is. Throw away how it executes.

The engine currently interprets the policy set on every request. It could
compile it once per policy version instead. A working prototype measures
**10 to 20x faster** than `engine.can()` today, in plain TypeScript, with no new
dependencies and no loss of runtime policy changes.

This document explains the idea, shows the measurements, and lists what it would
actually take.

---

## How the numbers were made

vitest 4.1.9, AMD Ryzen 9 9955HX. Scratch benchmarks live in
`packages/duck-iam/tmp/`, which is gitignored, so rerun or delete them freely.

Two things distorted my first run. Both are worth knowing if you rerun this.

**The harness floor is 34.0M ops/s.** An empty benchmark body measures 34.0M, so
anything reading above roughly 30M is not being measured, it is hitting the
timer. Every table below includes a control row so the floor is visible.

**String literals get constant-folded.** My first prototype called
`compiledCheck(mask, 'read', 'res-0')` with literals, so V8 folded the lookup key
into a constant. That read 31.8M. Rotating the inputs so nothing folds gives
9.3M. Every number here is from the rotating version.

---

## The idea

The policy set changes at most once a minute. Requests arrive constantly. Yet on
every single request the engine re-derives facts that could only have changed at
the last policy load:

- which policies could apply to this action and resource
- which rules inside them could match
- whether a wildcard covers this action
- how to split `subject.attributes.dept` into path segments
- what the combining algorithm yields

That is an interpreter. It walks a data structure and decides what to do, over
and over, at request rate.

A compiler walks it once per policy version and emits something that already
knows the answer. The request path then does a lookup and nothing else.

Nothing about authoring changes. Policies, rules, roles, `inherits`, conditions,
combining algorithms, the typed `createIam` config, all stay identical. Only the
step between "policies loaded" and "answer returned" is different.

---

## What gets removed, what gets built, what stays

**Removed from the request path** (still exists in the codebase, just no
longer runs per request):

- The `Map<'action\0resource'>` bucket lookup + per-bucket rule scan in
  `evaluate.ts` (`literalBuckets`, `evaluate.ts:265-321`) — replaced by a
  direct array index, no hashing, no scanning a bucket's rules.
- `rolesToPolicy` regenerating `subject.roles contains X` RBAC rules on every
  role-cache refresh (`rbac.ts:46-102`, every ~60s by default) — roles scatter
  straight into `allow`/`deny` bits at compile time instead; the generated
  rules never exist.
- Per-request wildcard expansion (`admin:*` matched against the live action
  set), dot-path splitting, and regex matching for role/attribute paths — all
  resolved once at compile time, baked into a cell or a closure.

**Built new:**

- The compiled table: one row per `(action, resource)` pair, each row tagged
  `CONSTANT` / `ROLE_MASK` / `DYNAMIC` (see below for the literal shape).
- The compile step itself — scatters roles (closing `inherits` once) and
  policy rules into cells.
- Atomic-swap + serve-stale-during-rebuild on invalidation.
- The scope overlay and multi-tenant sharing described further down.

**Stays exactly as-is — nothing here moves:**

- `createIam`'s config shape, policy/role authoring, `inherits`, combining
  algorithms — authoring is untouched (see "Nothing about authoring changes,"
  above).
- Every adapter (`getSubjectRoles`, `getSubjectAttributes`, `getSubjectScopedRoles`,
  ...) — still the only source of truth, still called the same way.
- `invalidatePolicies()` / `invalidateRoles()` / `invalidateSubject()` — reused
  as the compile trigger, not replaced by new machinery.
- The interpreter (`evaluate`/`evaluateFast`) — kept alive as `explain()`'s
  implementation, as the fallthrough for anything the table doesn't cover yet,
  and as the differential-testing oracle.
- The public API — `engine.can/check/explain/permissions` keep their exact
  signatures and return shapes. Only what runs underneath them changes.

---

## What a compiled table looks like

`createIam` already gives you the universe:

```ts
const access = createIam({
  actions: ['create', 'read', 'update', 'delete'] as const,
  resources: ['post', 'comment', 'user'] as const,
  roles: ['viewer', 'editor', 'admin'] as const,
})
```

Actions and resources are a closed set, so the space of `(action, resource)`
pairs is small and enumerable. Four by three here. Maybe twenty by a hundred in a
large app. Small enough to precompute a cell for every pair.

For each pair, gather every rule across every policy that could match it, and
sort the result into one of three kinds.

**Constant.** No conditions touch this pair, so the answer is a fixed boolean
decided at compile time. Request cost: one array read.

**Role mask.** The only conditions are RBAC role guards. Give every role an
integer and store a bitmask of the roles that grant this pair. Request cost: one
array read and one bitwise AND.

Combining is baked into that mask at compile time, not evaluated per request.
`deny-overrides` within a policy: keep two masks per cell, `allow` and `deny`,
one bit set per role that grants or denies this pair. The answer is
`(subjectMask & allow) !== 0 && (subjectMask & deny) === 0` — deny always wins,
same result a real deny-overrides interpreter would reach, just precomputed.
`allow-overrides` across policies: compile each policy's `allow`/`deny` pair
separately, then OR every policy's `allow` together and every policy's `deny`
together into the cell's final pair at compile time. A request never walks the
policy list — it reads one already-merged pair. This `allow`/`deny` shape is
reused as-is by the scope overlay (`baseAllow`/`baseDeny` below) and by the
`and`-mode fix further down — one mechanism, three places it applies.

**Dynamic.** Real attribute conditions are involved. Store the pre-filtered
candidate rules with each condition already turned into a closure. Request cost:
run one or two closures. No matching, no path splitting, no wildcard scanning.

### What it looks like as data

One struct-of-arrays, sized `nActions * nResources`, built once at compile time:

```ts
table = {
  kind:  Uint8Array(N),   // 0 = CONSTANT, 1 = ROLE_MASK, 2 = DYNAMIC
  value: Uint8Array(N),   // CONSTANT cells: 0 or 1
  allow: Uint32Array(N),  // ROLE_MASK / DYNAMIC cells: bit per role
  deny:  Uint32Array(N),  // same, for explicit deny
  rules: Array(N),        // DYNAMIC cells only: closure[]
}
idx = actionId * nResources + resourceId   // row-major flatten, same trick as a 2D grid
```

Roles are interned as powers of two — `viewer=0b001`, `editor=0b010`,
`admin=0b100` — so each role owns one bit no other role overlaps, and any
combination a subject holds is one number (`editor+admin = 0b110`) that
`&`/`|` can test as a set, with no collisions.

Against this doc's own example config (4 actions, 3 resources, `nResources=3`),
four representative rows:

| idx | (action, resource) | kind | allow | deny | rules | why |
|-|-|-|-|-|-|-|
| 3 | read, post | `ROLE_MASK` | `0b111` | `0` | – | every role can read |
| 2 | create, user | `CONSTANT` | – (`value=0`) | – | – | nobody grants it, default deny |
| 7 | update, comment | `DYNAMIC` | `0` | `0` | `[isOwner]` | pure ABAC, no role qualifies |
| 9 | delete, post | `DYNAMIC` | `0b100` | `0` | `[isOwner]` | admin bypasses, or owner |

Request-time lookup, same for every cell, one function:

```ts
function can(table, subjectMask, action, resource) {
  const idx = actionId[action] * nResources + resourceId[resource]
  switch (table.kind[idx]) {
    case CONSTANT:  return !!table.value[idx]
    case ROLE_MASK: return (subjectMask & table.allow[idx]) !== 0
                        && (subjectMask & table.deny[idx]) === 0
    case DYNAMIC:   return (subjectMask & table.allow[idx]) !== 0
                        || table.rules[idx].some(fn => fn(subject, resource))
  }
}
```

`idx=3` (`read, post`) with `subjectMask = editor (0b010)`: one multiply, one
array read, one AND — `2 & 7 = 2 ≠ 0` → allowed, done. `idx=2`
(`create, user`): one array read, no subject touched at all. `idx=7`
(`update, comment`): allow is `0`, falls to running `isOwner` — the only cell
kind that ever runs a closure, and only the closures that actually apply to
that exact cell.

**Which kind a cell ends up as, precisely:**

- `CONSTANT` is not just "nothing grants this pair." Two distinct cases land
  here: nothing touches the cell at all (default effect, `create, user`
  above), *or* something grants/denies it with zero conditions of any kind —
  no role check, no attribute check (e.g. "anyone can read the homepage").
  Both are fixed booleans because no condition, RBAC or ABAC, is left to
  evaluate.
- `ROLE_MASK` only ever uses `allow`/`deny`. `rules` stays empty — the moment
  any real condition touches the cell it stops being `ROLE_MASK`.
- `DYNAMIC` always has `rules` populated, but `allow`/`deny` are not
  necessarily empty. Pure-dynamic cells (`update, comment` above) leave them
  at `0`. Mixed cells (`delete, post` above) set both: a role can bypass the
  condition entirely (`allow=admin`), while everyone else still needs to pass
  `rules`.

Three problems from `ARCHITECTURE-PERF.md` disappear rather than get fixed:

- **Wildcards stop existing at runtime.** `admin:*` is expanded against the known
  action set at compile time, so the 3x cliff where one wildcard rule disables
  precompute for a whole policy cannot happen.
- **The RBAC rule explosion is gone.** No generated rules, no
  `subject.roles contains X` conditions, no quadratic blowup from flattening
  inheritance. Roles are integers, grants are bits.
- **Policy count stops mattering.** Cells are built from all policies once, so a
  request never iterates policies. 200 policies cost the same as one.

---

## Measured

Fixtures: 20 roles in a linear `inherits` chain, 8 actions, 20 resources, plus
two ABAC policies. Rotating inputs.

**Unconditional check, compiles to a constant**

| | ops/s | vs today |
|-|-------|----------|
| `engine.can()` today | 1,010,000 | baseline |
| `evaluateFast` today, no engine | 14,585,000 | 14x |
| compiled, Map key | 9,268,000 | **9.2x** |
| compiled, interned integer ids | 21,466,000 | **21.3x** |
| control: empty body | 33,996,000 | the floor |

**Pure RBAC check, compiles to a bitmask test**

| | ops/s | vs today |
|-|-------|----------|
| `engine.can()` today | 1,037,000 | baseline |
| `evaluateFast` today | 3,907,000 | 3.8x |
| compiled bitmask | ~21,000,000 | **~20x** |

`evaluateFast` drops from 14.6M to 3.9M here. That is the RBAC penalty showing
up: every generated RBAC rule carries a `contains` condition, so it can never use
the precomputed path.

**ABAC check with two conditions, compiles to closures**

| | ops/s | vs today |
|-|-------|----------|
| `engine.can()` today | 790,000 | baseline |
| `evaluateFast` today | 1,816,000 | 2.3x |
| compiled closure tree | ~10,000,000 | **~12x** |

**UI permission map, 40 checks for one subject**

| | ops/s | per check |
|-|-------|-----------|
| `engine.permissions()` today | 46,862 | 533 ns |
| compiled, 40 individual checks | 507,955 | 49 ns |
| compiled, pre-baked subject bitmap | at the floor | effectively free |

That last row matters for React apps. Once a subject's role mask is known, every
constant and role-mask cell can be baked into a bitmap for that subject, once.
After that, answering "can this user do X to Y" is a single array read. A page
asking 200 permission questions stops being a performance topic. It only covers
cells that do not depend on request attributes, so ownership rules still evaluate
normally, but most UI gating is role-shaped.

---

## Two details that matter

**Intern your strings.** The gap between 9.3M and 21.5M is entirely
`Map<string>` lookup versus indexing a flat typed array. Map every action and
resource to an integer at compile time and store cells in
`Uint8Array(nActions * nResources)`. A 2.3x difference for a mechanical change.

**Role count is a non-problem.** A JS number holds 32 role bits. Past that you
need `Uint32Array`. Measured:

| | ops/s |
|-|-------|
| single u32 mask, up to 32 roles | 34,103,000 |
| Uint32Array intersect, 1024 roles | 31,469,000 |
| Set membership over subject roles, sparse | 31,208,000 |

All three sit at the harness floor. The difference is unmeasurable. Pick
`Uint32Array` for density, or a sparse Set if subjects hold only a few roles.

---

## Runtime policy changes

This is the objection that decides the design, so it gets real space.

### "Compile" here means policy load, not build

CASL compiles at ability construction, in your code, and the result is immutable.
That is why CASL genuinely cannot do runtime policy changes.

This design compiles inside the engine, at policy load, triggered by invalidation
machinery that already exists. `savePolicy` already calls `invalidatePolicies()`,
which already forces a reload on the next request. The compile step hangs off
that same hook.

So the question is not whether policies can change. It is what a change costs.

### Three different things get called "dynamic"

**Dynamic decisions.** The answer depends on request data: is this user the
owner, is the document in draft. Compilation does not restrict this at all. These
are the dynamic cells, holding closures that read `subject` and `resource` at
request time.

**Dynamic assignments.** An admin grants a user a role. The most common dashboard
action, and it does not touch the table at all. Only that subject's mask changes.

**Dynamic policies.** An admin edits a rule or a role's permissions. This is the
only case that recompiles.

### What each one costs

The first prototype's compiler ran at 2.84 ms, but it did `roles.find()` inside a
triple-nested loop. Rewritten to scatter from roles and policies into cells with
no searching:

| Operation | Cost |
|-----------|------|
| Grant a user a role, recompute subject mask | **46 ns** |
| Edit one policy, incremental cell recompute | **43 ns** |
| Full rebuild, 20 roles / 10 actions / 20 resources | **15 µs** |
| Full rebuild, 50 roles / 20 actions / 100 resources | **75 µs** |
| Full rebuild, 200 roles / 40 actions / 500 resources | **472 µs** |

Table memory:

| World | Cells | Flat arrays |
|-------|-------|-------------|
| 20 roles / 10 actions / 20 resources | 200 | 1.0 KB |
| 50 roles / 20 actions / 100 resources | 2,000 | 9.8 KB |
| 200 roles / 40 actions / 500 resources | 20,000 | 97.7 KB |

### The number that settles it

A policy edit needs an adapter reload no matter what engine you run. That is a
database round trip, 1 to 10 ms for Postgres.

Compilation is pure CPU on data you already fetched. **15 µs to 472 µs of compile
sits inside a 1 to 10 ms reload you were already paying.**

It is also cheaper than something the engine does today. `rolesToPolicy` on a
20-role hierarchy measures **127 µs** and runs on every role cache refresh, which
is every 60 seconds by default. A full compile of a comparable world is **15 µs**.
Compiling the entire table is roughly **8x cheaper than the RBAC step you already
pay**, and it replaces it.

### Four properties that make it safe

**Atomic swap.** Build the new table into a fresh object, then assign one
reference. Readers holding the old reference finish against consistent data. No
locks, no torn reads. JavaScript gives this for free.

**Serve stale during rebuild, which beats today.** `invalidatePolicies()`
currently calls `.clear()` on both caches, so the next request misses and must
await the adapter round trip. Every request arriving in that window blocks. With
an immutable compiled artifact you keep answering from the old table until the
new one is ready, then swap. The latency blip on a policy edit disappears.

**Deopt to the interpreter.** You do not have to rebuild synchronously. Mark
affected cells dirty on write. A dirty cell falls through to today's
`evaluateFast`, which is always correct. Recompile dirty cells on the next idle
tick. The policy change takes effect immediately with zero rebuild latency on the
request path. This is how a JIT tiers.

**Multi-node needs nothing new.** `createRedisInvalidator` already broadcasts
invalidation. Compiled tables subscribe to the same events and each node
recompiles locally.

### A bonus you get for free

Single-role edits already go through `admin.saveRole()`, which always passes the
edited role's id to `invalidateRoles(roleId)` — that path already scans and
evicts only subjects holding that role, not the whole cache. The no-id form that
calls `subjectCache.clear()` on *every* cached subject is reached from exactly
one place today: the bulk `restoreSnapshot` path (`engine.libs.ts:395`), after a
snapshot import touches many roles at once and invalidating everything is the
conservative-but-correct call when you don't know which subjects any of them
affect.

**Fixable today, no rewrite needed:** `restoreSnapshot` already has the touched
role ids in hand (`snapshot.roles`, plus whatever it deleted). It can call
`invalidateRoles(roleId)` once per touched role — reusing the targeted path that
already exists — instead of the no-id nuke. That turns "clear every subject in
the process" into "clear only subjects touching one of the N changed roles,"
in the interpreter, today.

**What only the rewrite fixes:** even the targeted `invalidateRoles(roleId)`
path evicts every subject holding that role for *any* edit to it, including a
permissions-only edit that never changes who's affected. That happens because
`resolveEffectiveRoles` bakes inheritance into the cached subject, so the engine
cannot tell whether an edit changed *who has the role* or *what the role
grants*. A compiled table separates them: the subject cache holds assigned
roles, the table holds what roles grant. Editing a role's **permissions**
touches only the table and every cached subject stays valid. Only editing a
role's **inherits** invalidates subjects, because that really does change the
effective role set. Most role edits are permission edits.

---

## Scope and multi-tenancy: two axes that don't fit a flat table

Two of the gaps below — scope and per-tenant tables — look like they need a new
table dimension, which multiplies cell count by every value on that axis. Neither
does. Both compile down to a small overlay checked alongside the base cell, not a
bigger table. Same principle in both cases: most of the axis is identical
everywhere, so only compile the part that differs.

### Scope: an overwrite mask, not a table axis

Discord doesn't store a full permission table per channel either. It computes a
member's guild-level role permissions once, then applies a small channel-specific
overwrite — `(base | allow) & ~deny` — at read time. Explicit deny at the more
specific layer always wins. Scope in duck-iam is the same shape: most roles are
scope-agnostic, only some grants are scope-restricted.

Keep the `(action, resource)` table scope-free. Give each role-mask cell a second,
optional layer that only exists where a scope-conditioned rule actually touches
that cell:

```ts
cell = {
  baseAllow: u32,  baseDeny: u32,       // scope-agnostic grants
  scopeOverlay?: Uint32Array,           // [scopeId * 2] = allow, [scopeId * 2 + 1] = deny
}
```

If the scope set is small and enumerable (company vs. marketplace, a handful of
tenant tiers), intern it exactly like actions and resources and index the overlay
as a flat typed array — same 21M-vs-9M win the doc already measured for interning,
and it avoids a `Map` entirely. Request cost is one extra array read:

```ts
allow = cell.baseAllow | (overlay ? overlay[scopeId * 2] : 0)
deny  = cell.baseDeny  | (overlay ? overlay[scopeId * 2 + 1] : 0)
result = (subjectMask & allow) !== 0 && (subjectMask & deny) === 0
```

A cell with no scope-conditioned rule has no overlay at all — zero extra memory,
zero extra work. Only hierarchical/unbounded scope (an org tree, not a fixed
tier list) needs the dotted-type treatment below instead of a flat array.

### Multi-tenancy: share the common case, cap the rest

The doc's own worst case — a thousand tenants each holding an independent table —
assumes every tenant's policy set is unique. In practice most tenants run the
shipped defaults untouched; only the ones who've actually authored custom roles
or rules diverge. Three techniques, layered, in order of how much each buys:

1. **Structural sharing by content hash.** Canonicalize a tenant's
   `(roles ∪ policies)` — stable-sorted, stable-serialized — and hash it. Compile
   once per distinct hash, not once per tenant:
   `Map<contentHash, CompiledTable>` plus `Map<tenantId, contentHash>`. Tenants on
   identical, uncustomized policy sets collapse onto one shared table. A thousand
   tenants is likely single-to-low-double-digit distinct hashes in practice, not
   a thousand tables.
2. **Base + overlay for tenants who do customize.** Split each tenant's policy
   set into the shared system baseline (compiled once, globally) and their
   tenant-specific delta (typically a handful of custom roles or rules, checked
   as an overlay ahead of the base cell — same overlay shape as scope, above). A
   tenant who added three custom roles pays for three roles of table, not a
   second full copy of the grid.
3. **LRU-bounded resident set, reusing `IamLRUCache`.** For the genuinely
   distinct tail — where hashing and overlay stop saving much — don't precompile
   ahead of demand. Compile lazily on first request after invalidation (the
   natural behavior `IamLRUCache` already gives you), cap resident distinct
   tables the same way `_subjectCache` already caps at 1000 entries, evict LRU.
   An evicted tenant's next request just recompiles — 15-472µs, the same cost a
   cache miss pays today. Not a correctness issue, a rare extra compile.

Net: memory scales with *distinct customization*, not tenant count. The doc's
98MB worst case assumes zero sharing; (1) and (2) mean the realistic number is a
handful of shared base tables plus small deltas for the tenants who actually
diverge, and (3) caps the resident set regardless of how that plays out.

### Hierarchical scope: measured, partially — read the caveats

The performance half of this was reasoned from analogy at first, with zero
measurement. It has since been prototyped: `packages/duck-iam/tmp/hierarchical-scope.bench.ts`,
`npx vitest bench --run tmp/hierarchical-scope.bench.ts`. Simulated a subject
holding scope grants across a 50-org / 1,000-team / 25,000-repo universe, at
grant counts of 5, 50, and 500, comparing a per-subject trie walk against a
naive linear scan over the subject's raw grant rows (what an unmodified ABAC
condition would do today):

| Subject's grant count | trie walk | naive linear scan | speedup |
|-|-|-|-|
| 5 | 7.67M ops/s | 5.9M ops/s | 1.3x |
| 50 | 6.87M ops/s | 727K ops/s | 9.45x |
| 500 | 7.43M ops/s | 70K ops/s | **106x** |

Trie walk stays flat (6.9M-7.7M ops/s) from 5 to 500 grants — bounded by
hierarchy depth, not by how many scopes the subject holds, as claimed.
Trie *construction*, even for a 500-grant subject, measured 55.5µs — cheaper
than this doc's own "full rebuild, 200 roles" figure (472µs) elsewhere. The
"a bot/service account with hundreds of grants breaks this" worry was worth
checking; it doesn't.

**What that benchmark does not settle:**

- **Combining semantics — resolved and shipped.** Not a single toggle;
  `scopeMode: 'flat' | 'hierarchical'` (whether ancestors match at all) and
  `scopeCombine: 'union' | 'override'` (how matching levels combine) are two
  separate config knobs, same shape as `policyCombine` today. `'union'`
  (default) ORs every matching ancestor level's roles in — an org-level
  grant and a team-level grant both apply, GitHub's "org owner reaches every
  repo" behavior. `'override'` walks specific-to-general and stops at the
  first level with any grant — a repo-level assignment shadows the org
  level entirely rather than adding to it. Both are real code today:
  `enrichSubjectWithScopedRoles` in `engine.libs.ts`, config in
  `engine.types.ts`, 11+ tests in `engine.libs.enrich-scope.test.ts`. This
  is the *interpreter*-side fix (today's flat-role-list engine); the
  compiled-table design below still needs the equivalent at the cell level.
- **`DYNAMIC`-cell interaction — proposed, not built.** Gate before
  evaluate, don't fold into the closure: resolve the scope trie to an
  `{allow, deny}` mask first (deny wins outright — a scope-denied cell never
  reaches the rule closures), OR the surviving scope-allow into the
  subject's role mask, *then* run the `DYNAMIC` cell's rule closures against
  that combined mask exactly as they run today. Scope only ever widens or
  narrows which role-bits reach the condition check; it never bypasses a
  real ABAC condition. Unproven — no prototype exercises this path yet, see
  the plan below.
- **`TScope` has no notion of hierarchy today** (`extends string`, opaque) —
  and doesn't need one for `scopeMode`/`scopeCombine` above: those work on
  the *string value* of `scope` at request time (dot-split), not on the
  type. A real schema/adapter design for parent/child scope relationships
  is still a separate, unstarted task if hierarchy needs to be validated or
  queried structurally rather than just pattern-matched.

#### The shape it might take

GitHub's org→team→repo and Slack's org→workspace→channel are the same shape,
and it does not fit the flat overlay above — you cannot intern "every team
that will ever exist" as an array index. It is a different problem from the
"hierarchical dotted types" gap below, though: that gap is about resource
*types* nesting (`org.team.project.doc` as one type — rare). GitHub and Slack
have an ordinary closed set of resource types (repo, issue, channel, message)
with hierarchical *scope* on top — more common, and solvable without a dense
table.

**Grants are stored as paths, per subject, not globally.** `org-123`,
`org-123.team-456`, `org-123.team-456.repo-789`. A subject's own scope grants
are a handful of these — tens at most, never the system's total team/repo
count — so store them as a tiny `Map<scopePrefix, {allow, deny}>` per
subject, resolved and cached exactly the way `scopedRoles` already is today
(same `resolveSubject`, same TTL, no new global structure).

**Request time: walk the resource's own path from specific to general, first
match wins.** A repo at `org-123.team-456.repo-789` checks the subject's trie
at `repo-789`, then `team-456`, then `org-123`, stopping at the first hit —
the same "more specific wins" rule the flat scope overlay already uses
(`(base | allow) & ~deny`), just walked instead of indexed. Depth is 2-4
levels for anything shaped like GitHub or Slack, so this is a handful of
`Map.get` calls against a structure sized to *one subject's own grants*, not
a lookup against a system-wide unbounded set. Bounded by hierarchy depth,
never by team/repo/channel count — not O(1) in the strict sense, but not
O(N) either.

**Which direction wins has to be a policy choice.** Some apps want
most-specific-wins (a repo-level restriction beats an org-level grant); some
want any-ancestor-grants (an org owner reaches every repo underneath
regardless of team settings — how GitHub actually works). Same shape as
`policyCombine` today: a config option, not an assumption baked into the walk.

The performance shape of this is now measured, not guessed. The semantics
(combining rule, `DYNAMIC` interaction) and the `TScope` schema work are not
— see the caveats above before building against this. True hierarchical
resource *types* remain the separate, rarer, still-fully-open problem the gap
list below names.

---

## What the prototype does not do

The honest gap list. This is the actual work.

1. **Only `allow-overrides` across policies, `deny-overrides` within.** The `and`
   mode is harder because an applicable policy with no matching rule votes deny
   rather than abstaining, so you cannot merge policies into one cell. Fix:
   compile one allow/deny mask pair *per policy* that touches the cell, and AND
   the short list of per-policy answers together at request time. Still
   O(policies touching this cell) — typically 2-3 — not O(all policies), and
   still just array reads plus bitwise ops, no re-walk of conditions.
2. **No rule priority.** `first-match` and `highest-priority` need the ordering
   baked into the cell: sort the cell's rules/policies once at compile time,
   walk the fixed short array in that order at request time and stop at first
   match. Same complexity as the `and` case above — resolved by pushing the sort
   to compile time instead of doing it, or re-scanning for it, per request.
3. **No scoped roles.** Solved above, see "Scope and multi-tenancy."
4. **No wildcard expansion.** The prototype matched literals only. Real expansion
   against the action and resource universe is straightforward but must be exact.
5. **No `explain()`.** Keep the interpreter for it. It is development only and
   does not care about speed. This is a feature: the interpreter becomes your
   reference implementation.
6. **No hooks, metrics, or per-policy error isolation.** All additive.
7. **Atomic swap has to be deliberate.** It is one assignment, but the compiled
   artifact must be replaced as a unit so no request sees a half-built table.

### Real limits

**Resource instances are not a table dimension.** The usual first worry, and it
is unfounded. duck-iam's resource is `{ type, id, attributes }` and the table
keys on `type`. A million posts is one cell. The `id` only appears inside
conditions.

**Hierarchical dotted types are the real unbounded case.**
`org.team.project.doc` as a resource *type* cannot be densely tabled. You need
a literal table plus a prefix structure for dotted patterns, plus interpreter
fallthrough. This is still open. The far more common version of this — scope
nesting over an ordinary closed set of resource types, GitHub/Slack-shaped —
has a candidate shape sketched above, see "Hierarchical scope," but it is
unproven, not solved.

**Very wide worlds need a cap.** 200 actions by 5,000 resource types is a million
cells, roughly 5 MB and a rebuild in the tens of milliseconds. Set a cell budget
and stay interpreted above it.

**Per-tenant tables multiply.** Solved above, see "Scope and multi-tenancy" —
content-hash sharing, base/overlay split, and an LRU-bounded resident set.

**A pathological write rate inverts the tradeoff.** If policies changed more
often than requests arrived, compiling would lose. Add a governor: if the rebuild
rate crosses a threshold, stay interpreted.

---

## How to ship it without a rewrite

Do not replace the engine. Add the table as a fast path with fallthrough:

```
can(subject, action, resource):
  cell = table.lookup(action, resource)
  if cell exists  -> compiled answer
  else            -> today's evaluateFast, unchanged
```

Start narrow: literal actions and resources, `allow-overrides`, no scope, no
priority. Everything else falls through and behaves exactly as it does now. Then
widen coverage case by case. Each widening is independently testable.

**Use differential testing.** Run both engines on every request in staging,
assert the answers match, alert on divergence. Authorization is the one place
where a silently wrong answer is worse than a slow one, and this gives you a
mechanical proof of equivalence over real traffic instead of an argument. The
interpreter you already have is the oracle. Do not skip this.

---

## Implementation plan

Concrete, in order. Each phase is independently mergeable and independently
testable — no phase requires the next one to be safe to ship. Code below is
real TypeScript against this repo's actual types (`AccessControl.IRule`,
`AccessControl.IPolicy`, `AccessControl.IRole`), not the `any`-typed
prototypes in `tmp/` — those already proved the performance shape (see
"Measured" above); this section proves the shape compiles against the real
model and closes the scope/DYNAMIC gap those prototypes left open.

### File layout

```
src/core/engine/compiled/
  compiled.types.ts       # Cell, CompiledTable, CompileInput
  compiled.compile.ts      # compileTable(): (roles, policies) -> CompiledTable
  compiled.lookup.ts        # lookup(): the request-time O(1)/O(depth) path
  compiled.scope.ts         # scope trie build + walk (shared with engine.libs.ts)
  __tests__/
    compiled.differential.test.ts   # compiled vs evaluateFast, same inputs, must agree
```

Nothing here replaces `evaluate.ts`. It stays as the oracle differential
tests check against, and as the fallthrough for whatever the table doesn't
cover yet (wildcards, `first-applicable`, priority — see "Start narrow"
below).

### Phase 1 — table types and the compile step (RBAC + unconditional ABAC only)

```ts
// compiled.types.ts
export const enum CellKind {
  CONST_DENY = 0,
  CONST_ALLOW = 1,
  ROLE_MASK = 2,
  DYNAMIC = 3,
}

export interface CompiledTable {
  readonly nActions: number
  readonly nResources: number
  readonly actionId: ReadonlyMap<string, number>
  readonly resourceId: ReadonlyMap<string, number>
  readonly roleId: ReadonlyMap<string, number>
  /** idx = actionId(a) * nResources + resourceId(r) for every array below. */
  readonly kind: Uint8Array
  /** Valid when kind === ROLE_MASK, or as a role-bypass fast path when kind === DYNAMIC. */
  readonly allow: Uint32Array
  readonly deny: Uint32Array
  /** Valid when kind === DYNAMIC. Rule closures compiled ahead of time, in priority/algorithm order. */
  readonly dynamic: (DynamicTest[] | undefined)[]
}

export interface DynamicTest {
  readonly allow: boolean
  readonly test: (req: unknown) => boolean
}
```

```ts
// compiled.compile.ts
import { type AccessControl } from '../../types'
import { CellKind, type CompiledTable } from './compiled.types'

export function compileTable(
  actions: readonly string[],
  resources: readonly string[],
  roles: readonly AccessControl.IRole[],
  policies: readonly AccessControl.IPolicy[],
): CompiledTable {
  const nA = actions.length
  const nR = resources.length
  const actionId = new Map(actions.map((a, i) => [a, i]))
  const resourceId = new Map(resources.map((r, i) => [r, i]))
  const roleId = new Map(roles.map((r, i) => [r.id, i]))

  const kind = new Uint8Array(nA * nR)
  const allow = new Uint32Array(nA * nR)
  const deny = new Uint32Array(nA * nR)
  const dynamic: (DynamicTest[] | undefined)[] = new Array(nA * nR)

  // Close inheritance once, then invert: holders[roleIdx] = every role whose
  // effective set contains roleIdx. Same rule resolveEffectiveRoles uses today.
  const byId = new Map(roles.map((r) => [r.id, r]))
  const effective: number[][] = roles.map((r) => {
    const out: number[] = []
    const seen = new Set<string>()
    const walk = (id: string, depth: number) => {
      if (depth > 32 || seen.has(id)) return
      seen.add(id)
      const idx = roleId.get(id)
      if (idx !== undefined) out.push(idx)
      for (const p of byId.get(id)?.inherits ?? []) walk(p, depth + 1)
    }
    walk(r.id, 0)
    return out
  })
  const holders: number[][] = roles.map(() => [])
  effective.forEach((anc, i) => anc.forEach((a) => holders[a]!.push(i)))

  // Scatter RBAC grants (each role's own permissions -> every role that inherits it).
  for (let i = 0; i < roles.length; i++) {
    for (const perm of roles[i]!.permissions) {
      if (perm.action === '*' || perm.resource === '*') continue // wildcards fall through, phase 3
      const a = actionId.get(perm.action)
      const r = resourceId.get(perm.resource)
      if (a === undefined || r === undefined) continue
      const idx = a * nR + r
      let m = 0
      for (const h of holders[i]!) m |= 1 << (h % 32)
      allow[idx]! |= m
      if (kind[idx] === CellKind.CONST_DENY) kind[idx] = CellKind.ROLE_MASK
    }
  }

  // Scatter unconditional ABAC allow rules to CONST_ALLOW. Conditional rules: phase 2.
  for (const p of policies) {
    for (const rule of p.rules) {
      const cond = rule.conditions
      const hasCond = cond && ('all' in cond || 'any' in cond || 'none' in cond)
      if (hasCond) continue
      for (const act of rule.actions) {
        if (act === '*') continue
        for (const res of rule.resources) {
          if (res === '*') continue
          const a = actionId.get(act)
          const r = resourceId.get(res)
          if (a === undefined || r === undefined) continue
          const idx = a * nR + r
          if (rule.effect === 'allow' && kind[idx] !== CellKind.DYNAMIC) kind[idx] = CellKind.CONST_ALLOW
        }
      }
    }
  }

  return { nActions: nA, nResources: nR, actionId, resourceId, roleId, kind, allow, deny, dynamic }
}
```

`lookup()` for this phase — the whole request-time path:

```ts
// compiled.lookup.ts
export function lookup(table: CompiledTable, mask: number, action: string, resource: string): boolean {
  const a = table.actionId.get(action)
  const r = table.resourceId.get(resource)
  if (a === undefined || r === undefined) return false
  const idx = a * table.nResources + r
  const k = table.kind[idx]
  if (k === CellKind.CONST_ALLOW) return true
  if (k === CellKind.ROLE_MASK) return (mask & table.allow[idx]!) !== 0
  return false // CONST_DENY, or DYNAMIC (phase 2)
}
```

**Ship this behind the fallthrough from "How to ship it without a rewrite"
above.** `lookup()` returning from a cell that exists is the compiled
answer; a cell this phase never populates (any conditional rule, any
wildcard) is `CONST_DENY` by zero-init, which is wrong to trust silently —
so phase 1 must track which cells it actually touched (a `has: Uint8Array`
bitset alongside `kind`, or reuse `kind !== CONST_DENY || explicitlyDenied`)
and fall through to `evaluateFast` on an untouched cell. Differential test
this before merging.

### Phase 2 — DYNAMIC cells (real ABAC conditions)

Reuses `compileCondition`/`compileGroup` already proven in
`tmp/compiled.bench.ts` (closures over dot-paths, no interpretation at
request time), wired against the real `IConditionGroup` shape instead of
`any`:

```ts
// added to compileTable()'s policy loop, replacing the "continue" on hasCond
if (hasCond) {
  const test = compileConditionGroup(rule.conditions) // walks IConditionGroup, same operators evaluate.ts supports
  for (const act of rule.actions) {
    if (act === '*') continue
    for (const res of rule.resources) {
      if (res === '*') continue
      const a = actionId.get(act)
      const r = resourceId.get(res)
      if (a === undefined || r === undefined) continue
      const idx = a * nR + r
      kind[idx] = CellKind.DYNAMIC
      ;(dynamic[idx] ??= []).push({ allow: rule.effect === 'allow', test })
    }
  }
}
```

```ts
// compiled.lookup.ts, extended
export function lookup(table: CompiledTable, mask: number, action: string, resource: string, req?: unknown): boolean {
  const a = table.actionId.get(action)
  const r = table.resourceId.get(resource)
  if (a === undefined || r === undefined) return false
  const idx = a * table.nResources + r
  const k = table.kind[idx]
  if (k === CellKind.CONST_ALLOW) return true
  if (k === CellKind.ROLE_MASK) return (mask & table.allow[idx]!) !== 0
  if (k === CellKind.DYNAMIC) {
    if ((mask & table.allow[idx]!) !== 0) return true // role-bypass fast path, no closures run
    const tests = table.dynamic[idx]!
    for (let i = 0; i < tests.length; i++) if (tests[i]!.test(req)) return tests[i]!.allow
    return false
  }
  return false
}
```

`compileConditionGroup` is new work, not yet prototyped: `evaluate.ts`'s
condition operators (`eq`, `in`, `contains`, `before`/`after`, etc. — see
`src/core/conditions/`) need a compiled closure per operator, mirroring
`tmp/compiled.bench.ts`'s `compileCondition` but covering the full operator
set instead of the 3-operator subset that file used to prove the shape.

**Differential test this phase against `evaluateFast` on every operator**,
not just the 2 rules `tmp/compiled.bench.ts` used — that file proved
closures are fast, not that every operator compiles correctly.

### Phase 3 — scope: the trie + the DYNAMIC interaction (closes the open gap)

This is what "Hierarchical scope" above resolves in design but never wired
into the compiled path. Per-subject, not per-cell — the trie lives on the
resolved subject, same place `scopedRoles` does:

```ts
// compiled.scope.ts — reuses engine.libs.ts's scopeAncestors, no new logic
import { scopeAncestors } from '../engine.libs' // export it, currently module-private

export function buildScopeTrie(
  scopedGrants: readonly { scope: string; allow: number; deny: number }[],
): Map<string, { allow: number; deny: number }> {
  const trie = new Map<string, { allow: number; deny: number }>()
  for (const g of scopedGrants) {
    const e = trie.get(g.scope)
    if (e) {
      e.allow |= g.allow
      e.deny |= g.deny
    } else trie.set(g.scope, { allow: g.allow, deny: g.deny })
  }
  return trie
}

/** scopeCombine: 'union' sums every matching ancestor; 'override' stops at the first (see doc above). */
export function resolveScopeMask(
  trie: Map<string, { allow: number; deny: number }>,
  scope: string,
  combine: 'union' | 'override',
): { allow: number; deny: number } {
  let allow = 0
  let deny = 0
  for (const level of scopeAncestors(scope)) {
    const hit = trie.get(level)
    if (!hit) continue
    allow |= hit.allow
    deny |= hit.deny
    if (combine === 'override') break
  }
  return { allow, deny }
}
```

```ts
// compiled.lookup.ts, final form — scope gates before DYNAMIC runs, per the design above
export function lookupScoped(
  table: CompiledTable,
  baseMask: number,
  scopeTrie: Map<string, { allow: number; deny: number }> | null,
  scope: string | undefined,
  scopeCombine: 'union' | 'override',
  action: string,
  resource: string,
  req?: unknown,
): boolean {
  let mask = baseMask
  if (scopeTrie && scope != null) {
    const { allow: scopeAllow, deny: scopeDeny } = resolveScopeMask(scopeTrie, scope, scopeCombine)
    if ((mask & scopeDeny) !== 0 || (scopeAllow !== 0 && false)) {
      // deny gates the whole cell before DYNAMIC ever runs
      mask &= ~scopeDeny
    }
    mask |= scopeAllow
  }
  return lookup(table, mask, action, resource, req)
}
```

(The `scopeDeny`/`scopeAllow` mask combine above is the literal
`(base | allow) & ~deny` overlay from "Scope: an overwrite mask, not a
table axis" earlier in this doc — `lookupScoped` is that formula applied to
the subject's role mask before it reaches `lookup()`, so `ROLE_MASK` and
`DYNAMIC` cells both get scope for free without their own scope-aware
branch.)

**Differential test against the real interpreter run with `scopeMode`/
`scopeCombine` already shipped** (`enrichSubjectWithScopedRoles` — this is
real code today, not a prototype) — the compiled and interpreted paths must
agree on every `(subject, scope, action, resource)` combination the
existing 15 `engine.libs.enrich-scope.test.ts` cases cover, run through
both paths.

### Phase 4 — wire into the engine, differential-test in staging

Exactly "How to ship it without a rewrite" above: `can()`/`check()` try
`lookupScoped()` first, fall through to `evaluateFast` on any cell the
table doesn't cover. Rebuild the table on every cache invalidation
(`cache.invalidatePolicies`/`invalidateRoles`) — full rebuild, not
incremental, per "The number that settles it" above (rebuild cost is
already dwarfed by the DB round trip that triggered it).

**What phase 4 does not attempt:** wildcard actions/resources, `priority`,
`first-applicable`/`first-match`/`highest-priority` combining algorithms,
policy `targets`. All of those fall through to the interpreter unchanged —
narrowing the compiled table's coverage is always safe; it just means more
requests take the slow path until a later phase widens it.

### What's still unproven after this plan

- Phases 1-2 are re-derivations of what `tmp/compiled.bench.ts` and
  `tmp/dynamic.bench.ts` already benchmarked — expected to hold, not
  re-measured against the real operator set yet.
- Phase 3's `lookupScoped` has never been run, benchmarked, or differential
  tested — it exists here as code, not as a proof. `tmp/hierarchical-scope.bench.ts`
  proved the trie-walk shape in isolation; it never combined with a
  `DYNAMIC` cell in the same benchmark.
- No phase above has been built. This section is the plan the next work
  session executes, phase by phase, each with its own differential-test
  gate before merge — not a claim that any of it is done.
- **Update, mid-build (Task 4 review):** the compiled table's per-cell design
  is sound under `policyCombine: 'allow-overrides'` but NOT under `'and'`
  (the production default) or `'first-applicable'`. Under `'and'`,
  `evaluateFast` requires every non-`targets`-excluded policy — including the
  always-present RBAC-derived policy whenever any role has any permission —
  to independently vote `true`; a policy's *absence* of a matching rule at a
  cell is real information (an implicit deny vote) the compiled table has no
  way to represent per-cell. Confirmed empirically: a role granting a cell
  alongside a co-located DYNAMIC policy whose condition fails diverges
  (compiled says allow, `evaluateFast('and')` says deny). **Superseded** by
  "What actually shipped" below — the gate-behind-`allow-overrides`/
  fall-through resolution described here was never built; the compiler was
  made `'and'`-aware instead, closing the gap directly.

### What actually shipped

Phase 4 as written above (`lookupScoped()` first, fall through to
`evaluateFast` on any uncovered cell, gated to `allow-overrides` only) was
implemented, then explicitly rejected: production mode replaces the
interpreter fully, unconditionally, for every `policyCombine` mode — no
flag, no per-request fallthrough.

What changed from every phase above:

- **No `experimentalCompiledTable` flag.** `mode: 'production'` always
  builds and uses the compiled table. There is no non-compiled production
  path left to fall through to.
- **`'and'`-mode soundness solved at compile time, not deferred.** Every
  touched cell where more than one *ABAC* flat policy applies gets
  classified `DYNAMIC` with one phantom zero-rule vote group per
  flat-eligible policy absent at that cell — `combiners[algorithm]([],
  defaultEffect)` already resolves an empty rule list correctly, so this
  needed only compile-time bookkeeping, not new runtime combining logic.
  `'and'` is now as sound as `'allow-overrides'`, at full compiled speed.
  `'first-applicable'` remains excluded (`mode: 'production'` rejects it at
  construction, unrelated to this design).
- **RBAC is one independently-computed vote, never folded into the ABAC
  phantom-vote bookkeeping above.** The first cut of this design tried to
  fold the RBAC grant-mask bit into the *same* per-cell DYNAMIC machinery as
  ABAC policies (a `ROLE_MASK` cell kind, a `foldRbacIntoAnd` flag). A final
  whole-branch review caught that this double-counted RBAC whenever a role
  held both a simple permission (the fast mask bit) and a complex one
  (scope/conditions-restricted, evaluated via a synthesized residual
  policy): the two halves became two independent `'and'` voters instead of
  the single OR'd vote one `__rbac__` policy actually represents, so a role
  with *any* complex permission anywhere could spuriously veto *every*
  simple grant it held, system-wide, under the default `policyCombine:
  'and'`. Fixed by making RBAC its own top-level vote —
  `rbacVote()` in `compiled.lookup.ts` — computed as the mask-bit fast path
  OR (on a miss) the residual policy's own vote, falling back to
  `defaultEffect` only when neither matches. `CellKind.ROLE_MASK` and
  `foldRbacIntoAnd` no longer exist; `CompiledTable.rbacResidual` is its own
  field, deliberately kept out of `residualPolicies` so it can never again
  be double-counted as an independent voter.
- **A 33rd role silently aliases the first role's grant bit.** The same
  review caught that the grant mask is a plain 32-bit integer with no cap
  on role count — `1 << 32 === 1` in JS, so role index 32 (and 64, 96, ...)
  collides with role index 0. `compileTable()` now throws past 32 roles
  rather than silently granting an unrelated subject's permissions to a
  33rd role's holders.
- **The engine wiring fed `compileTable` the wrong policy list.** The
  review also caught that `engine.ts` passed `compileTable` the
  RBAC-merged policy list (`loadAllPolicies()`, which already includes a
  synthesized `__rbac__` policy) instead of the raw adapter policies
  `compileTable` expects to derive RBAC from itself — a second, independent
  route to the same double-counting bug above, and (before the `rbacVote`
  fix) enough on its own to force every ROLE_MASK-eligible cell into the
  slower DYNAMIC path even with zero real ABAC policies configured. Fixed
  by switching to the raw `loadPolicies()`.
- **`lookupScoped()` and the scope trie (Phase 3) were deleted, not
  shipped.** They assumed a raw per-scope bitmask-grant data model that
  doesn't exist in this engine — real scoped-role grants are merged into
  `subject.roles` as plain role names by `enrichSubjectWithScopedRoles`
  before any compiled lookup runs, so scope needed no dedicated compiled
  representation at all.
- **Residual policies replace "fall through to the interpreter."** A
  policy with `targets`, a non-literal action/resource pattern, or a role
  permission with `scope`/`conditions` is excluded from the flat model and
  evaluated per-request via `evaluatePolicyFast` (the same function this
  doc called "the interpreter," now reused as the residual-policy
  evaluator, not as a fallback). `lookup()` combines the flat vote with one
  vote per residual policy and always returns a definitive `boolean`.
- `evaluateFast`/`evaluatePolicyFast`/`evaluate`/`evaluatePolicy` remain
  public exports — nothing was deleted from the API. What's retired is
  `engine.ts` ever calling `evaluateFast` in production mode.

Two pre-existing correctness bugs, unrelated to any phase above, surfaced
and were fixed during this work: `isWildcard()` only recognized bare `'*'`,
not `':*'`/`'.*'` prefix patterns (rules using those silently compiled as
inert literal cells); and the role-permission compiler ignored
`IPermission.scope`/`conditions`, granting an unconditional bit regardless
of restriction. A third, in the interpreter itself
(`evaluate.ts`'s `matchCandidate` skipping match verification for any
wildcard-shaped rule, a false-ALLOW bug reachable from the public
`evaluateFast`/`evaluatePolicyFast`) was also found and fixed.

### Measured: the actual wired path

`tmp/compiled-full.bench.ts` benches the real integration point —
`engine.can()` in `mode: 'production'` (compiled table) against
`mode: 'development'` (interpreter) — through the full stack: subject
resolution, hooks, scope enrichment, everything. vitest 4.1.9, same
machine as "How the numbers were made" above.

| Request shape | production (compiled) | development (interpreter) | Speedup |
|---|---|---|---|
| RBAC mask-covered (`update`/`post`) | 2.39M ops/s | 0.44M ops/s | **5.40x** |
| DYNAMIC-covered (`read`/`post`, condition-gated) | 1.62M ops/s | 0.96M ops/s | **1.69x** |

Numbers are post the RBAC-vote redesign below (`rbacVote()` computed as
its own top-level vote, mask-hit-first). That redesign was a correctness
fix, not a perf pass, but it measurably *beat* the already-fixed
dynamic-import numbers on both shapes — the mask-hit fast path now
short-circuits before ever calling `evaluatePolicyFast` on the RBAC
residual, where the old design paid that cost unconditionally on every
single lookup regardless of whether the mask bit already granted access.

Still short of the standalone prototype's 10-20x — expected, since this
number includes everything the prototype benchmarks factored out (subject
resolution, hooks, scope enrichment, cache lookups). It's still a real,
unconditional win on every production request, and it closes out all three
"still unproven" bullets above: Phases 1-2 hold in the real integration,
`lookupScoped` is moot (deleted), and `'and'`-mode is sound and fast.

Two regressions surfaced and were fixed along the way, neither by intent —
both self-discovered, one via this benchmark and one via a dispatched
final whole-branch review:

- The first wired version of `engine.ts` used
  `await import('./compiled/compiled.lookup')` inside the hot
  `authorize()`/`permissions()` paths — a dynamic import *per request*,
  intended for code-splitting but paid on every call, not just the first.
  That made production measurably *slower* than the interpreter it was
  replacing (0.70M vs 0.93M ops/s on the ROLE_MASK case). Fixed by making
  `lookup` a static top-level import; `compileTable` stays a dynamic
  import since it only runs on table (re)build, not per request.
- The review that followed caught three release-blocking correctness bugs
  in that same wiring — RBAC double-voting under `'and'`, the engine
  feeding `compileTable` an already-RBAC-merged policy list, and 32-bit
  role-mask overflow past 32 roles — documented above under "What actually
  shipped." All three are fixed and covered by new regression tests
  (`compiled.engine-wiring.test.ts`, `compiled.compile.test.ts`,
  `compiled.differential.test.ts`); the numbers in the table above are
  measured *after* that fix.

---

## Verdict

| Option | Speed | Effort | Risk | Do it? |
|--------|-------|--------|------|--------|
| Incremental fixes from `ARCHITECTURE-PERF.md` | 1.0M to ~7.6M | days | low | **Yes, first** |
| Compiled engine | ~7.6M to 10-20M | weeks | medium | **Yes, after** |

A compiled engine with interning should reach **10 to 20M ops/s** for
`engine.can()`, against 1.01M today.

For context, CASL measures 16.9M on `ability.can()`. A compiled duck-iam would be
somewhere between competitive with and faster than the library it currently
reports being 2x behind, while keeping runtime-mutable policies, which CASL does
not have. You would keep the property the README sells and stop paying for it on
every request.

All of this is plain TypeScript. Typed arrays, bitwise operations, and closures
built at load time. No `eval`, no `new Function`, no native modules, no new
dependencies. It runs identically in Node, Bun, Deno, the browser, and edge
runtimes.

Do the incremental fixes first. They are 7x for a few days of low-risk work, and
they will tell you whether you ever need the rest.
