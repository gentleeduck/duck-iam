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

**Dynamic.** Real attribute conditions are involved. Store the pre-filtered
candidate rules with each condition already turned into a closure. Request cost:
run one or two closures. No matching, no path splitting, no wildcard scanning.

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

Today `invalidateRoles()` with no role id calls `subjectCache.clear()`. Editing
any role definition throws away every cached subject, so every following request
pays a full subject resolution, three adapter calls each. One dashboard click
causes a thundering herd.

That happens because `resolveEffectiveRoles` bakes inheritance into the cached
subject, so the engine cannot tell whether a role edit changed *who has the role*
or *what the role grants*.

A compiled table separates them. The subject cache holds assigned roles, the
table holds what roles grant. Editing a role's **permissions** touches only the
table and every cached subject stays valid. Only editing a role's **inherits**
invalidates subjects, because that really does change the effective role set.
Most dashboard edits are permission edits.

---

## What the prototype does not do

The honest gap list. This is the actual work.

1. **Only `allow-overrides` across policies, `deny-overrides` within.** The `and`
   and `first-applicable` modes need thought. `and` is harder because an
   applicable policy with no matching rule votes deny rather than abstaining, so
   you cannot merge policies into one cell. You would compile per-policy
   sub-cells and combine them.
2. **No rule priority.** `first-match` and `highest-priority` need the ordering
   baked into the cell.
3. **No scoped roles.** Scope adds a dimension: a third table axis, or a
   scope-keyed mask per cell.
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
`org.team.project.doc` cannot be densely tabled. You need a literal table plus a
prefix structure for dotted patterns, plus interpreter fallthrough. This is the
largest piece of unglamorous work in the design.

**Very wide worlds need a cap.** 200 actions by 5,000 resource types is a million
cells, roughly 5 MB and a rebuild in the tens of milliseconds. Set a cell budget
and stay interpreted above it.

**Per-tenant tables multiply.** A thousand tenants at 9.8 KB is nothing. At
97.7 KB it is 98 MB, which is noticeable. Share tables between tenants with
identical policy sets, or cap how many stay resident.

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
