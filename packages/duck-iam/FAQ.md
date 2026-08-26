# duck-iam: why it is fast, and the questions people ask

A short, honest explanation of where the speed comes from and answers to the
questions that come up first. Everything here points at real code in
`packages/duck-iam/src`.

---

## Part 1: why is it fast?

The short version: **an authorization check almost never does real work.**
The expensive parts (loading policies, flattening role inheritance, parsing
patterns, building indexes) all happen once and get cached. What is left on the
hot path is a couple of `Map` lookups.

### 1. There are two evaluators, not one

`src/core/evaluate/evaluate.ts` ships two paths:

| Mode | Function | Returns |
|------|----------|---------|
| `development` | `evaluate` | full `IDecision` object (which rule fired, why, duration, timestamp) |
| `production` | `evaluateFast` | plain `boolean` |

The dev path allocates a decision object per policy, calls `performance.now()`
twice, and builds a human-readable `reason` string. The production path does
none of that. Same rules, same semantics, no allocation. You pick with
`mode: 'production'` on the engine.

### 2. Every policy gets an index, built once

`indexPolicy()` in `evaluate.libs.ts` turns a policy's rule array into:

- `byActionResource`: a `Map` keyed by `` `${action}\0${resource}` `` so an exact
  match is one lookup instead of a scan over every rule.
- `wildcardAny`: only the rules that contain `*`, scanned separately. A policy
  with no wildcards never touches this list.
- `precomputed`: a `Map<action, Map<resource, boolean>>` of final verdicts.

The index is stored in a `WeakMap` keyed by the policy object, so it is built
once per policy and garbage collected when the policy is dropped. No manual
cache management, no leak.

### 3. The common case is a single Map lookup

For rules with literal actions and resources and no conditions, `indexPolicy`
runs the combining algorithm ahead of time and stores the answer. At request
time:

```ts
const actionMap = idx.precomputed.get(action)
if (actionMap) {
  const precomputed = actionMap.get(resType)
  if (precomputed !== undefined) return precomputed   // done
}
```

That is O(1). No rule iteration, no condition evaluation, no allocation. This is
the same trick CASL uses, applied to the subset of rules where it is safe (the
precompute is skipped entirely when a policy has wildcard rules, because a
wildcard could override the cached answer).

### 4. Nothing on the hot path touches the database

`IamEngine` keeps five caches (`engine.ts`), all LRU with TTL
(`src/shared/cache.ts`):

- policies (single entry)
- roles (single entry)
- the generated RBAC policy (single entry)
- the merged policy list handed to the evaluator (single entry)
- resolved subjects (default 1000 entries)

Default TTL is 60 seconds, tunable with `cacheTTL`. A steady-state request hits
cache five times out of five and never calls the adapter.

### 5. Concurrent cache misses collapse into one adapter call

Cold start under load is the classic stampede: 500 requests arrive, the cache is
empty, and 500 identical `SELECT * FROM policies` go out. The engine holds an
in-flight promise per loader (`_inFlight` in `engine.ts`, used by
`engine.loaders.ts`), so the first miss does the work and everyone else awaits
the same promise. Subjects are single-flighted per subject id.

### 6. String work is memoized

Two things in the hot path would otherwise be recomputed on every check:

- **Dot paths.** `subject.attributes.department` is split and validated once and
  memoized in a path cache (`resolve.ts`, capped at 10k entries, FIFO eviction).
- **Regexes.** The `matches` operator compiles patterns once into a regex cache
  (`conditions.libs.ts`, capped at 256).

Both caches are **per engine instance** by default, which matters for
multi-tenancy: one tenant flooding cold patterns cannot evict another tenant's
entries.

### 7. Role inheritance is flattened at load, not per request

`resolveEffectiveRoles` and `rolesToPolicy` (`src/core/rbac/rbac.ts`) walk the
`inherits` graph once when roles are loaded, and the result is cached. A request
from a user with `admin -> editor -> viewer` does not re-walk that chain, it
just sees a flat role list. Depth is capped at 32 and cycles are cut by a
visited set, so a bad role graph cannot hang the check.

### 8. Short-circuits everywhere

- Policy `targets` are checked before the index is even consulted, so a policy
  that does not apply to this action or resource costs three `some()` calls and
  returns `null`.
- `combine: 'and'` returns `false` on the first deny.
- `combine: 'allow-overrides'` returns `true` on the first allow.
- `deny-overrides` returns `false` the moment it sees a matching deny rule.
- Condition groups use `every` / `some`, which short-circuit natively.

### 9. You pay nothing for features you do not use

- No `onMetrics` hook configured means `performance.now()` is never called.
- `explain()` is a dynamic `import()`, so production bundles never include it.
- The 12 KB validator is lazy-loaded on the first admin write, not at boot.
- Adapters, server middleware, and client wrappers are separate entry points and
  tree-shake away.

### 10. Batch checks amortize

`engine.permissions(subjectId, checks)` resolves the subject and loads policies
**once** for the whole batch, memoizes scoped-role enrichment per scope, and
accepts `{ telemetry: false }` to skip per-check metrics (roughly 2x throughput
on hot UI gates).

### 11. `preload()` removes the cold first request

`await engine.preload()` at boot warms the merged policy cache. The first real
request then runs at steady-state speed instead of paying load plus index cost.

---

## Part 2: the questions people ask

### How fast is it, really?

Benchmarked with vitest bench against 5 other JS authorization libraries, simple
RBAC check, higher is better:

| Library | ops/sec |
|---------|---------|
| @casl/ability | 16,857,000 |
| **@gentleduck/iam** (production mode) | 8,233,000 |
| easy-rbac | 5,003,000 |
| @rbac/rbac | 2,884,000 |
| accesscontrol | 674,000 |
| casbin | 143,000 |

8 million checks per second means a check costs roughly 120 nanoseconds. In any
real request, that is invisible next to a single database round trip.

Run it yourself: `bun run bench` in `packages/duck-iam`.

### CASL is faster. Why?

Because CASL compiles its rules into a hash table when you build the ability
object, and that object is immutable. duck-iam supports policies that change at
runtime (an admin edits a role, a policy is written to the database, a Redis
message invalidates the cache), so it carries one extra `Map` lookup and a
cache-validity check per call. That is the whole 2x.

It is a deliberate trade: dynamic policies for 120ns instead of 60ns. If your
rules are static and known at build time, CASL is the better tool.

### Does every check hit my database?

No. Reads go through the LRU caches described above. The adapter is called on
cache miss or expiry only. With a 60 second TTL and steady traffic, that is once
a minute per cache, not once per request.

### Then how do I make a policy change take effect immediately?

Three options, use whichever fits:

1. `engine.cache.invalidatePolicies()` after a write on the same process.
2. `createRedisInvalidator({ client: redis })` passed as `invalidator`, which
   broadcasts invalidation to every node.
3. Lower `cacheTTL` and accept the extra adapter load.

Admin writes through `engine.admin` invalidate the relevant caches for you.

### How big is it?

Core engine as typically imported is about 15 KB gzipped. Each adapter is
1.7 to 6 KB, each server middleware 2.4 to 3.7 KB, each client 1.2 to 2.0 KB.
The 41 KB headline is the worst case where you `import * from '@gentleduck/iam'`
and pull the whole barrel. Use subpath imports and real deployments land at
15 to 25 KB.

### What does it depend on?

The core engine has zero runtime dependencies. The only entry in `dependencies`
is `uuid`, and it is imported solely by the Drizzle schema helpers
(`src/adapters/drizzle/schema/*.ts`). If you do not use Drizzle, it never loads.
React, Vue, and Drizzle are optional peer dependencies.

### Is it RBAC or ABAC?

Both, in one evaluation pass. Roles are compiled into ABAC rules by
`rolesToPolicy()`, so a role grant and an attribute policy go through the same
evaluator and combine with the same algorithms. There is no second code path to
reason about.

### Can it accidentally allow something?

It fails closed by default. `defaultEffect` is `deny`. Setting it to `allow`
throws at construction unless you also pass `allowFailOpen: true`, and even then
it logs a loud startup warning. Evaluation errors, adapter timeouts, and subject
resolution failures all resolve to deny, not allow.

A single broken policy does not break the whole check either: it is treated as
not applicable and routed to the `onPolicyError` hook, so one bad row cannot
take down authorization for everyone.

There is also a `failOpen` signal on the metrics hook, set only when an allow
came from the default rather than from a matching rule. Chart it and you will
notice a mass policy deletion or a broken adapter immediately.

### Why does it debug well if it is optimized?

Because the optimization only applies to production mode. In development mode
`engine.explain()` returns the full trace: which policies were considered, which
rules matched, which conditions passed or failed with actual versus expected
values, and a readable summary. `explain()` throws in production mode by design,
and its code is a separate lazy chunk, so the debug affordance costs the
production bundle nothing.

### Is it safe for multi-tenant deployments?

Yes, with the usual pattern of one engine per tenant. The regex and dot-path
caches are per engine instance, so a hostile tenant flooding unique patterns
cannot evict another tenant's cached entries. If you share one engine, call
`iamFlushSharedCaches()` periodically to bound any single tenant's influence on
the process-wide fallback caches.

### What are the built-in limits?

| Setting | Default | What it does |
|---------|---------|--------------|
| `cacheTTL` | 60s | cache lifetime |
| `maxCacheSize` | 1000 | subject cache entries |
| `adapterTimeoutMs` | 5000 | hard `AbortController` timeout per adapter read |
| `maxPolicies` / `maxRoles` | 10,000 | load-time caps, fail closed when exceeded |
| role inheritance depth | 32 | fixed |
| condition nesting depth | fixed cap | deeper nesting fails closed |
| `permissions()` batch | 1024 checks | refuses larger batches |

### What frameworks and databases work with it?

Server: Express, NestJS, Hono, Next.js, plus a generic adapter.
Client: React, Vue, vanilla JS.
Storage: Memory, File, Prisma, Drizzle (Postgres, MySQL, SQLite), Redis, HTTP.

The core is framework agnostic. All of the above are separate entry points.

### When is it *not* fast?

Being straight about the slow paths:

- **Cold start.** The first request after boot pays adapter load plus index
  build. `preload()` exists for exactly this and is roughly a 15x improvement on
  that first call.
- **Heavy wildcard policies.** Rules containing `*` cannot be precomputed and are
  scanned linearly in `wildcardAny`. Prefer literal action and resource pairs
  where you can.
- **Regex conditions.** The `matches` operator is the most expensive of the 18
  operators, even with the compiled-regex cache. Use `eq`, `in`, or
  `starts_with` when they express the same thing.
- **Very large policy sets.** Index build cost is linear in rule count and paid
  on each cache refresh. 10,000 policies with a 60 second TTL means rebuilding
  every minute.
- **Development mode in production.** It allocates a decision object per policy
  per request. That is the point of the mode switch.

### How well tested is it?

1,056 test cases across 51 test files, plus mutation testing via Stryker,
adapter compliance suites shared across all six adapters, and benchmarks against
five competing libraries.

---

## The one-paragraph answer

duck-iam is fast because a check is almost pure lookup. Policies, roles,
flattened inheritance, and resolved subjects are cached with TTL and
single-flighted on miss. Each policy's rules are indexed once into a `Map` held
in a `WeakMap`, and unconditional literal rules have their verdict precomputed,
so the common case is one `Map` lookup returning a cached boolean. Production
mode returns raw booleans with no allocation, dot paths and regexes are
memoized, unused features cost nothing because they are lazily imported, and
everything short-circuits. It lands within 2x of CASL while still supporting
policies that change at runtime.
