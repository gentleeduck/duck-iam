# duck-iam engine: architecture and where the time actually goes

A walkthrough of how a permission check flows through the engine, followed by
the measured cost of every layer and the specific changes worth making.

Everything below is measured, not guessed. Several things I expected to be
problems turned out to be free, and one thing nobody would suspect turned out
to be the single biggest cost in the whole check. Both are recorded.

**How these numbers were produced.** vitest 4.1.9, AMD Ryzen 9 9955HX, scratch
benchmarks in `packages/duck-iam/tmp/arch*.bench.ts` (that directory is
gitignored, so they are yours to rerun or delete). Run one with
`npx vitest bench --run tmp/arch.bench.ts`. Absolute nanosecond figures are
machine specific. The ratios are what matter.

---

## 0. Resolved: the published numbers are reproducible again

This section originally reported that `test/benchmark.bench.ts` failed at
import (`MemoryAdapter is not a constructor` - the class had been renamed to
`IamMemoryAdapter` but the benchmark and the docs still imported the old
name). That has since been fixed: `test/benchmark.bench.ts` imports
`IamMemoryAdapter` (commit `c9216515`), and `README.md`'s performance table
was regenerated from a real run against `mode: 'production'` (commit
`03ba56f4`). Run `bun run bench` to reproduce.

---

## 1. The architecture, layer by layer

There are five layers. A check falls through all of them.

```
  engine.can(subjectId, action, resource)
      |
  [1] ENTRY          validate subjectId, catch everything, fail closed
      |
  [2] LOAD           subject cache  -> adapter.getSubjectRoles/Attributes
      |              merged cache   -> policies + generated RBAC policy
      |              (LRU + TTL, single-flighted on miss)
      |
  [3] PREPARE        normalise roles, enrich scoped roles, run beforeEvaluate,
      |              stamp environment.now
      |
  [4] EVALUATE       for each policy:
      |                 targets check      -> skip policy entirely
      |                 indexPolicy()      -> WeakMap, built once
      |                 precomputed table  -> O(1) answer, done
      |                 literal bucket     -> Map<action\0resource>
      |                 wildcard scan      -> linear
      |                 conditions         -> resolve path, run operator
      |              then combine across policies
      |
  [5] REPORT         afterEvaluate / onDeny / onMetrics hooks
```

Layer 4 is the part everyone thinks about and the part the README benchmarks.
Layers 1 to 3 are where the time actually goes.

### The two evaluators

`mode: 'production'` runs `evaluateFast`, which returns a bare boolean.
`mode: 'development'` runs `evaluate`, which builds an `IDecision` per policy
with a reason string, a duration, and a timestamp. The repo's own benchmark puts
that at **12.9x** (496K/s vs 6.4M/s).

`mode` defaults to `'development'`. Anyone who does not explicitly pass
`mode: 'production'` is running the 13x slow path in production. See finding 6.

### The three caching layers

They are easy to confuse because they solve different problems:

| Layer | Where | Keyed by | Lifetime |
|-------|-------|----------|----------|
| Data caches | `IamLRUCache` in the engine | `'all'`, `'merged'`, subject id | TTL, default 60s |
| Rule index | `WeakMap` in `evaluate.libs.ts` | the policy object itself | until the policy is GC'd |
| String memos | `Map` for regex and dot paths | pattern / path string | until capacity, then evicted |

The rule index is the well designed one. Keying a `WeakMap` on the policy object
means a new policy array from a cache refresh automatically gets a fresh index
and the old one is collected, with no invalidation code to get wrong.

---

## 2. Where the time actually goes

One warm `engine.can()` in production mode costs about **950 nanoseconds**.
Here is what it is spent on. Each line was measured separately, so treat this as
attribution rather than a profiler trace, but it accounts for the total closely.

| Step | Cost | Share |
|------|------|-------|
| Subject cache read (LRU churn on a 500-entry map) | ~478 ns | 50% |
| Promise chain, 4 nested async functions | ~277 ns | 29% |
| Merged policy cache read (1-entry map) | ~90 ns | 9% |
| `evaluateFast` on a small policy set | ~66 ns | 7% |
| `ensureEnvNow` spread plus `Date.now()` | ~34 ns | 4% |
| Request object, signals object, guards | ~40 ns | 4% |

**The evaluator is 7% of a real check.** The README optimises and advertises the
7%. The other 93% is cache bookkeeping and promise machinery.

That is the whole thesis of this document. Confirmed end to end:

```
evaluateFast (raw, sync)          14,937,000 ops/s
engine.can() prod, all warm        1,083,000 ops/s   13.8x slower
engine.can() dev,  all warm          435,000 ops/s   34.3x slower
```

And a hand written synchronous version of the same warm check, doing the same
evaluation with the same policy:

```
engine.can()          1,012,000 ops/s
canSync()             9,589,000 ops/s   9.5x faster
```

Nothing about authorization requires that 9.5x. It is the cost of routing a
fully cached answer through four `async` functions and an LRU that rewrites
itself on every read.

---

## 3. Findings, worst first

### Finding 1: the subject cache rewrites its own Map on every read

**Impact: about 50% of a warm check. This is the biggest single item.**

`IamLRUCache.get()` (`src/shared/cache.ts:33`) does this on every hit:

```ts
this._map.delete(key)     // remove
this._map.set(key, entry) // re-insert at the end, so iteration order = recency
```

That is the standard trick for LRU on a `Map`, and on a small map it is fine.
On a map holding hundreds of entries, deleting and re-inserting on every single
read makes V8 repeatedly churn the map's backing store.

Measured, on a 500-entry map:

| Read strategy | ops/s | per read |
|---------------|-------|----------|
| Current: `delete` + `set` + `Date.now()` | 2,092,000 | 478 ns |
| Stamp a counter on the entry, no Map mutation | 31,762,000 | 31 ns |
| Floor: bare `Map.get` | 33,534,000 | 30 ns |

**15x**, landing within 6% of a bare `Map.get`. With rotating keys instead of one
hot key it is a smaller but still real 2.5x (9.9M/s vs 24.9M/s). The hot key case
is not artificial: it is exactly what one busy subject making many requests looks
like.

The default `maxCacheSize` is 1000, so this is the default configuration.

**Fix.** Stop mutating the Map on read. Store `used` on the entry and bump it:

```ts
get(key: string, now = Date.now()): V | undefined {
  const entry = this._map.get(key)
  if (!entry) { this._misses++; return undefined }
  if (now > entry.expiresAt) { this._map.delete(key); this._misses++; return undefined }
  entry.used = ++this._tick
  this._hits++
  return entry.value
}
```

Eviction then scans for the lowest `used` instead of taking the first key. That
makes eviction O(n) instead of O(1), which is the right trade: reads happen
constantly, evictions happen when the cache is full. If even that scan bothers
you, sample 8 random entries and evict the oldest of those, which is what Redis
does and is indistinguishable from true LRU in practice.

**Risk: low.** Contained to one class with its own tests. The only visible
change is eviction order under memory pressure, which is not part of the
contract.

### Finding 2: four of the five caches hold one entry and still do LRU work

**Impact: about 9% of a warm check.**

```ts
this._policyCache      = new IamLRUCache(1, ttl) // single entry
this._roleCache        = new IamLRUCache(1, ttl)
this._rbacPolicyCache  = new IamLRUCache(1, ttl)
this._mergedPolicyCache = new IamLRUCache(1, ttl)
this._subjectCache     = new IamLRUCache(maxSize, ttl)
```

Four caches with `maxSize: 1`, holding the fixed keys `'all'`, `'rbac'`,
`'merged'`. Recency ordering across a single entry can never change anything, yet
every read pays a `delete`, a `set`, a `Date.now()`, and a string hash.

| | ops/s | per read |
|-|-------|----------|
| `IamLRUCache.get()` on a 1-entry cache | 11,050,000 | 90 ns |
| Plain slot read with a caller supplied clock | 33,392,000 | 30 ns |

**3x**, for a cache that is structurally incapable of using the feature.

**Fix.** A `SingleSlot<V>` holding `{ value, expiresAt }` and nothing else. Same
`get`/`set`/`clear`/`stats` shape so the loaders do not change. Finding 1's fix
subsumes most of this, so do that one first and measure again.

**Risk: very low.**

### Finding 3: a fully cached check still goes through four async functions

**Impact: about 29% of a warm check.**

The call chain on a complete cache hit, where no I/O happens at all:

```
can()                    async
  await _resolveSubject  async -> subjectCache.get() -> hit, return
  await authorize        async
    await _loadAllPolicies async -> mergedPolicyCache.get() -> hit, return
    evaluateFast                   sync
```

Every one of those `async` functions allocates a promise and schedules a
microtask even when it returns an already-computed value. Measured with nothing
in the functions but the awaits:

| | ops/s |
|-|-------|
| sync call | 33,791,000 |
| 1 await | 11,580,000 |
| 3 awaits | 6,542,000 |
| 5 awaits | 3,607,000 |

Roughly 277 ns to await your way down to a value you already had.

**Fix, and be honest that this is the invasive one.** The loaders genuinely need
to be async on a miss. The pattern that handles both is to return `T | Promise<T>`
and only await when it is actually a promise:

```ts
function loadAllPolicies(deps): AccessControl.IPolicy[] | Promise<AccessControl.IPolicy[]> {
  const cached = deps.mergedPolicyCache.get('merged')
  if (cached) return cached          // sync, no promise allocated
  return loadAllPoliciesAsync(deps)  // the existing async body
}
```

Callers then do `const p = loadAllPolicies(deps); const policies = isPromise(p) ? await p : p`.
Ugly, and it has to be threaded through `authorize` and `can`, but it is the only
way to reach the sync path without a second API.

The cheaper alternative is a separate `canSync()` that requires warm caches and
throws otherwise. Less invasive, but it splits the API and pushes the warm/cold
decision onto users.

Recommendation: do findings 1 and 2 first, re-measure, then decide. Once the
cache reads drop from 568 ns to about 60 ns, the promise chain becomes the
majority of what is left and the case for this gets much stronger. It may also
turn out that 300 ns per check is simply fine for your users, in which case skip
it. Do not start here.

**Risk: medium to high.** Touches the control flow of the primary code path,
including its fail-closed error handling. Wants its own branch and a full test
run.

### Finding 4: evaluation is linear in total policy count, not matching policy count

**Impact: 4x at 50 policies, 40x at 200. Grows without bound.**

`evaluateFast` loops every policy in the array and calls `evaluatePolicyFast` on
each. A policy targeted at `billing:*` still costs a function call, a WeakMap
lookup, and up to three `some()` calls on every single request, forever, even
though it can never match a `read` on `post`.

| Policies (1 matches) | ops/s | per check |
|----------------------|-------|-----------|
| 1 | 15,153,000 | 66 ns |
| 10 | 3,891,000 | 257 ns |
| 50 | 765,000 | 1,307 ns |

**Fix.** Bucket policies by target action once, at load time, next to where the
merged list is already assembled. Policies with no targets or wildcard targets go
into an always-check list. Prototyped and measured:

| Policies | Current | Action-bucketed | Speedup |
|----------|---------|-----------------|---------|
| 10 | 3,655,000 | 9,940,000 | 2.7x |
| 50 | 932,000 | 9,921,000 | 10.6x |
| 200 | 251,000 | 9,618,000 | 38.3x |

The bucketed version stays flat at about 9.6M/s regardless of how many policies
exist, because it only evaluates the ones that could possibly apply.

Build it in `loadAllPolicies` and hang it off the merged array, or key another
`WeakMap` on that array so it invalidates exactly when the policy list does, the
same trick `indexPolicy` already uses.

**One caveat, and it matters.** My first attempt at this benchmark showed the
index being 8% *slower*. I had put the matching policy first with
`allow-overrides`, so the current code short-circuited on policy one and the
comparison measured nothing. The numbers above are from the corrected version
with the matching policy last. Worth knowing because it means the win depends on
policy ordering, and the flat 9.6M/s is the honest floor rather than the best case.

**Risk: low to medium.** Purely additive. The correctness requirement is that a
policy is never wrongly excluded, so wildcard and untargeted policies must fall
into the always-check list. Property test it against the current implementation
over random policy sets.

### Finding 5: RBAC rule count is quadratic in inheritance depth

**Impact: structural. Gets worse as the role hierarchy grows.**

Two things compound here.

**First, permissions are flattened per role.** `collectPermissions` walks the
`inherits` chain and copies every ancestor's permissions into the descendant's
rule set. Measured, with a linear inheritance chain:

| Hierarchy | Distinct permissions | Generated rules | Blowup |
|-----------|---------------------|-----------------|--------|
| 5 roles x 4 perms | 20 | 60 | 3x |
| 10 roles x 5 perms | 50 | 275 | 5.5x |
| 20 roles x 5 perms | 100 | 1,050 | 10.5x |

That is `p * n * (n+1) / 2`, quadratic in depth.

**And here is the part that makes it fixable: the flattening is redundant.**
`resolveSubject` already calls `resolveEffectiveRoles`, which closes the role set
over `inherits`. A subject assigned `admin` arrives at the evaluator with
`roles: ['admin', 'editor', 'viewer']` already. So `viewer`'s own generated rule,
guarded by `subject.roles contains viewer`, already matches. Copying viewer's
permissions into admin's rules produces a second rule that matches the same
request for the same reason.

**The caveat, which is real.** `collectPermissions` applies `perm.scope ?? role.scope`,
so an inherited permission picks up the *inheriting* role's scope. Drop the
flattening and it keeps the *defining* role's scope instead. For unscoped roles
these are identical. For scoped roles they are not. So the fix is: emit only
`role.permissions` when the role has no `scope`, and keep flattening for scoped
roles. Test that specific case first, because it is the one that breaks.

**Second, every generated RBAC rule carries a condition**, the
`subject.roles contains <role>` guard. The precompute table in `indexPolicy`
skips any rule with conditions. So the RBAC policy, which is usually the largest
policy and is evaluated on every request, can never use the fast path:

| | ops/s |
|-|-------|
| unconditional rule, precomputed hit | 15,631,000 |
| one `contains` condition, full path | 3,764,000 |

**4.15x**, paid on every RBAC check.

**Fix.** Stop expressing RBAC as generated ABAC rules on the hot path. Build a
direct index once, when roles load:

```ts
Map<action, Map<resource, Set<roleId>>>
```

Then a check is two Map lookups and a Set membership test per subject role.
Prototyped against the 1,050-rule generated policy above:

| | ops/s |
|-|-------|
| `evaluateFast` on the generated RBAC policy | 3,308,000 |
| Direct role index lookup | 27,112,000 |

**8.2x**, and the quadratic rule blowup disappears entirely.

There is a cold path cost too. `rolesToPolicy` on that 20-role hierarchy runs at
7,858/s, which is **127 microseconds**, paid on every role cache refresh (every
60 seconds by default, and after every role write).

Keep `rolesToPolicy` for `explain()`, which needs real rule objects to trace.
That path is development only and does not care.

**Risk: medium.** It is a real behavioural surface: scoped roles, per-permission
conditions, and the interaction with `policyCombine` all have to keep working.
But the RBAC test suite is the thing that should catch regressions, and it exists.
Do it after findings 1, 2, and 4.

### Finding 6: `mode` defaults to `'development'`

**Impact: ~2.5x, on anyone who forgets.** (The 13x/34x figures in section 1
are `evaluateFast` raw vs. `engine.can()`; the number that matters for *this*
footgun is prod vs. dev, directly below.)

```ts
this._mode = config.mode ?? 'development'
```

Forget to pass `mode`, and production runs the tracing evaluator: an `IDecision`
object per policy per request, `performance.now()` twice, and a formatted reason
string that nothing reads.

```
engine.can() prod    1,083,000 ops/s
engine.can() dev       435,000 ops/s
```

**Fix.** Default from the environment, and let the explicit option win:

```ts
this._mode = config.mode ?? (process.env.NODE_ENV === 'production' ? 'production' : 'development')
```

Guard the `process` access for non-Node runtimes. If changing the default is too
breaking for a minor release, at minimum emit a startup warning when
`NODE_ENV === 'production'` and `mode` is `'development'`, the same way the
`defaultEffect: 'allow'` fail-open warning already works.

**Risk: low, but it is a behaviour change.** `explain()` throws in production
mode, so anyone relying on `explain()` with `NODE_ENV=production` breaks. Ship it
in a major, or ship the warning now and the default later.

### Finding 7: one wildcard rule disables precompute for the entire policy

**Impact: 3x, silently, and it looks like nothing changed.**

```ts
if (wildcardAny.length === 0 && (algo === 'deny-overrides' || ...)) {
  // build the precomputed table
}
```

One wildcard rule anywhere in a policy, even one that provably cannot match the
request, drops the whole policy off the O(1) path. Measured with a policy of 51
literal rules, then the same policy plus one `deny admin:* on secret` rule,
checking `read` on `post`:

| | ops/s |
|-|-------|
| 51 literal rules, no wildcard | 15,593,000 |
| Same plus 1 unrelated wildcard rule | 5,233,000 |

**2.98x** for adding a rule that cannot possibly apply.

The conservatism is correct in principle. A wildcard rule *might* override the
precomputed answer, so precomputing without checking is wrong.

**Fix.** Narrow the bail-out from per-policy to per-key. When building the
precomputed entry for `(action, resource)`, check whether any wildcard rule could
match that specific pair. If none can, the precomputed answer is still valid.
That check happens once at index build time, not per request, so it can afford
to be thorough.

The cheap 80% version: if every wildcard rule's action prefix fails to match the
action, precompute for that action anyway.

**Risk: medium.** This is the correctness-critical part of the evaluator. A wrong
precomputed entry is a silently wrong authorization decision, which is the worst
possible bug in this codebase. Property test it: generate random policies with
wildcards, evaluate every (action, resource) pair both with and without
precompute, assert the answers are identical. Do not ship it on reasoning alone.

### Finding 8: the batch loop rebuilds request objects per check

**Impact: about 7% of a batched check.**

`permissions()` is already the fast path, and correctly so. It resolves the
subject once and loads policies once, which is why it beats a loop of `can()`:

| | per check |
|-|-----------|
| 20x `engine.can()` | 858 ns |
| `permissions()` x20 | 473 ns |
| `permissions()` x20, `telemetry: false` | 457 ns |

Note that `telemetry: false` buys 3%, not the "~2x throughput" the README claims.
That claim should be corrected or re-measured.

Inside the loop each check allocates a resource object, a request object, and
then `ensureEnvNow` spreads both the request and its environment again. Four
objects per check, two of them purely to stamp a clock value.

| | ops/s |
|-|-------|
| spread request + environment | 15,462,000 |
| no spread, `now` already present | 32,683,000 |

**Fix.** Stamp `now` once before the loop rather than per check, since a batch is
one logical instant anyway. And hoist the parts of the request that do not change
between checks. Small, safe, mechanical.

**Risk: very low.**

---

## 4. Things I expected to be slow that are not

Recording these so nobody spends a weekend on them. All measured.

**Building the `${action}\0${resource}` index key is free.** I assumed the string
concatenation was a per-request allocation worth removing with a nested Map. It
is not: template key build 33,694,000 ops/s, flat Map lookup including the key
build 33,687,000 ops/s, nested Map lookup 32,005,000 ops/s. The nested version is
marginally *slower*. V8 handles short string concatenation better than an extra
Map indirection. **Leave `byActionResource` exactly as it is.**

**`Reflect.get` in `resolve()` is not the problem.** Reflect.get loop 26,284,000
ops/s, plain bracket access loop 25,930,000 ops/s. Statistically identical. Keep
`Reflect.get`, it is there for prototype safety and it costs nothing.

**The per-call dependency bag is free.** `_loaderDeps()` and `_cacheBag()` build a
fresh 10-field object on every call and I assumed that was garbage per request.
Building it: 34,003,000 ops/s. Reusing a frozen one: 33,723,000 ops/s. V8's escape
analysis removes it entirely. **Leave them alone**, they are good for readability
and cost nothing.

**The rule index itself is well built.** `indexPolicy` on a cache hit runs at
24,384,000 ops/s, and rule count inside a policy barely matters: 5 rules
6,821,000 ops/s, 50 rules 6,977,000 ops/s, 500 rules 6,970,000 ops/s. Flat from 5
to 500 rules. The index does exactly what it was designed to do. The scaling
problem is *across* policies (finding 4), not within one.

**Single-flight, the WeakMap keying, and lazy imports are all correct.** No
changes suggested. The `WeakMap`-on-policy-object trick in particular is the
cleanest thing in the codebase: it makes index invalidation impossible to get
wrong because it is tied to object identity rather than to a version number
somebody has to remember to bump.

---

## 5. What to do, in order

Ordered by measured payoff divided by risk. Re-measure between each one, because
they interact: fixing the cache reads changes what fraction the promise chain
represents.

| # | Change | Expected | Risk | Scope |
|---|--------|----------|------|-------|
| 0 | ~~Fix `MemoryAdapter` in the benchmark and docs~~ | unblocks measurement | none | **done** - see §0 |
| 1 | Stop Map churn on `IamLRUCache.get` (finding 1) | ~40% off a warm check | low | one class |
| 2 | `SingleSlot` for the four 1-entry caches (finding 2) | ~5% more | very low | one class |
| 3 | Default `mode` from `NODE_ENV`, or warn (finding 6) | ~2.5x for anyone who forgot | low | a few lines |
| 4 | Cross-policy target index (finding 4) | 2.7x at 10, 38x at 200 policies | low-med | loaders plus evaluator |
| 5 | Hoist request building in `permissions()` (finding 8) | ~7% of batched checks | very low | one loop |
| 6 | Direct RBAC role index (finding 5) | 8.2x on RBAC, kills the quadratic | medium | rbac plus evaluator |
| 7 | Per-key precompute bail-out (finding 7) | 3x on wildcard policies | medium | needs property tests |
| 8 | Sync path for fully cached checks (finding 3) | up to 9.5x, less after 1 and 2 | med-high | primary code path |

Steps 0 through 3 are roughly a day and should get a warm `engine.can()` from
about 950 ns to somewhere near 450 ns without touching the evaluator or any
public behaviour. Steps 4 through 6 are where the scaling story lives and matter
most for anyone with a real policy set or a deep role hierarchy. Steps 7 and 8
are the ones to think hardest about before starting, and 7 is the only item on
this list where a mistake produces a wrong authorization decision rather than a
slow one.

## The short version

The engine's evaluator is genuinely good and does not need work. Rule indexing,
the `WeakMap` keying, precompute, and single-flight are all correct and fast, and
rule count inside a policy is essentially free from 5 rules to 500.

The costs are everywhere else. Half of a warm check is an LRU cache rewriting its
own backing Map on every read. A third is promise machinery wrapped around values
that are already in memory. Scaling is linear in total policy count rather than
matching policy count, and the RBAC layer generates a quadratic number of rules
that then cannot use the fast path it would most benefit from.

None of that is visible in the current benchmarks, because they call
`evaluateFast` directly and never touch the layers that cost the money.
