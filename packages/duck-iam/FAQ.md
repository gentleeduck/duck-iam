# duck-iam: why it is fast, and the questions people ask

Where the speed comes from, and the questions that come up first. Every claim
here points at code in `packages/duck-iam/src`.

---

## Part 1: why is it fast?

The short version: **an authorization check almost never does real work.**
The expensive parts (loading policies, flattening role inheritance, parsing
patterns, building indexes) all happen once and get cached. What is left on the
hot path is a couple of `Map` lookups.

### 1. There are two evaluators, and `mode` does not pick between them

The interpreter has two entry points. `src/core/evaluate/evaluate.ts` defines
them as `evaluate` / `evaluateFast`; the package exports them through
`evaluate.public.ts` under their public names:

| Export | Returns |
|------|---------|
| `iamEvaluate` | full `IDecision` object (which rule fired, why, duration, timestamp) |
| `iamEvaluateFast` | plain `boolean` |

**Neither is what `engine.can()` answers from.** The compiled table
(`core/engine/compiled/`) produces the verdict in *both* modes; `development`
additionally runs the interpreter to attach `reason` / `policy` / `rule`
provenance and throws if the two disagree. So `mode` buys you provenance and a
cross-check, not a different evaluator, and the interpreter's fast path is not
reachable from `can()` at all. See §11.

Both are reachable as direct exports, as are the single-policy pair
`iamEvaluatePolicy` / `iamEvaluatePolicyFast`. All four take `defaultEffect` as
an argument and throw on `'allow'` unless you also pass `allowFailOpen: true`,
the same gate the engine applies. That route runs no validator: the engine
validates on `admin.savePolicy` / `admin.import` and the persistent adapters
re-validate on read, but calling `iamEvaluate()` yourself on a hand-built policy
skips both.

### 2. Every policy gets an index, built once

`indexPolicy()` in `evaluate.libs.ts` turns a policy's rule array into:

- `byActionResource`: a nested `Map<action, Map<resource, rules>>` so an exact
  match is a lookup instead of a scan. It is deliberately *not* keyed by a
  joined `` `${action}\0${resource}` `` string - that key is not injective, and
  an embedded NUL let a rule fire for an unrelated request in production only.
- three wildcard buckets, not one: `byActionWildcardResource`,
  `byResourceWildcardAction`, and `wildcardBoth` for patterns with no literal
  side left to key on.
- `precomputed`: a `Map<action, Map<resource, boolean>>` of final verdicts, built
  only when no wildcard rules exist, since those could override the result.

The index is stored in a `WeakMap` keyed by the **`rules` array**, not the policy
object - `readonly rules` is a compile-time annotation only, and keying on the
policy meant replacing a policy's rules served the stale index for the object's
whole lifetime, so production kept granting what the interpreter had already
stopped granting. `length` and `algorithm` are recorded alongside so an append
or an algorithm change also invalidates.

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
just sees a flat role list. The walk stops at depth 32 and cuts cycles with a
shallowest-depth memo - `bestDepth` records the shallowest depth each role was
reached at and short-circuits a re-reach at the same or greater depth - so a bad
role graph cannot hang the check. A plain visited set would pin each role to the
depth it was first reached at, and two set-equal `inherits` arrays in different
orders would then resolve to different permissions.

### 8. Short-circuits everywhere

- Policy `targets` are checked before the index is even consulted, so a policy
  that does not apply to this action or resource costs three `some()` calls and
  returns `null`.
- `combine: 'and'` returns `false` on the first deny.
- `combine: 'allow-overrides'` returns `true` on the first allow.
- `deny-overrides` returns `false` the moment it sees a matching deny rule.
- Condition groups use `every` / `some`, which short-circuit natively.

### 9. You pay nothing for features you do not use

- `performance.now()` is sampled only when `onMetrics`, `afterEvaluate` or
  `onDeny` is wired. With none of the three, a check never times itself.
- `explain()` is a dynamic `import()`, so production bundles never include it.
- The 12 KB validator is lazy-loaded on the first admin write, not at boot.
- Adapters, server middleware, and client wrappers are separate entry points and
  tree-shake away.

### 10. Batch checks amortize

`engine.permissions(subjectId, checks)` resolves the subject and loads policies
**once** for the whole batch and memoizes scoped-role enrichment per scope. That
is where the win is: 473 ns per check against 858 ns for a loop of 20 `can()`
calls. `{ telemetry: false }` additionally skips the per-check `onMetrics`
emission, worth about 3% on top (457 ns) - useful on hot UI gates, not a
throughput multiplier. Batches over 1024 checks are refused.

### 11. `preload()` removes the cold first request

`await engine.preload()` at boot warms the merged policy cache. The first real
request then runs at steady-state speed instead of paying load plus index cost.

It also builds the compiled permission table - in both modes, since the table
now produces the verdict everywhere. A config with more than 32 roles cannot be
represented in it, and `preload()` is where you find that out: the engine warns
once, falls back to the interpreter, and `healthCheck().compiledTable` reports
the table as unavailable from then on. The answers stay correct; only the
throughput changes.

`preload({ validator: true })` does one more thing, and it is the only place the
package does it: it validates every stored policy and role. The write path
validates, the read path never has, so a row written by a migration or a seed
script is evaluated exactly as stored — and an invalid **deny** can silently
never fire. Run it at boot in any deployment where something other than
`engine.admin` writes those tables; it throws with the count and the offending
ids.

---

## Part 2: the questions people ask

### How fast is it, really?

See [`README.md`'s performance section](./README.md#performance) for the
numbers against 5 other JS authorization libraries: the bare rule-matching
benchmark and the real `engine.can()` entry point (adapter + hooks + subject
resolution + compiled table), which are two different things worth keeping
separate. They are anchored there to the version they were measured at, 5.6.0,
so a stale figure is visible as one. Kept in one place here instead of duplicated, since a
second copy is a second thing to go stale when the benchmark is re-run.

The short version: `engine.can()` in `mode: 'production'` runs at roughly
1M+ ops/sec - sub-microsecond per check, invisible next to a single database
round trip in any real request.

Run it yourself: `bun run bench` in `packages/duck-iam`.

### CASL is faster. Why?

Because CASL compiles its rules into a hash table when you build the ability
object, and that object is immutable. duck-iam supports policies that change at
runtime (an admin edits a role, a policy is written to the database, a Redis
message invalidates the cache), so it carries one extra `Map` lookup and a
cache-validity check per call. That is the whole 2x.

That 2x is the rule-matching row of the README table - `iamEvaluateFast()`
against a pre-built CASL ability, roughly 130ns a call against 60ns. The
`engine.can()` row is a wider gap because it is measuring a wider job: adapter,
hooks, subject resolution and cache checks are in that number and are not in
CASL's. If your rules are static and known at build time, CASL is the better
tool.

### Does every check hit my database?

No. Reads go through the LRU caches described above. The adapter is called on
cache miss or expiry only. With a 60 second TTL and steady traffic, that is once
a minute per cache, not once per request.

### Then how do I make a policy change take effect immediately?

Three options, use whichever fits:

1. `engine.cache.invalidatePolicies()` after a write on the same process.
2. `createIamRedisInvalidator({ client: redis, secret })` passed as `invalidator`, which
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
(`src/adapters/drizzle/{pg,mysql,sqlite}/*.schema.ts`). If you do not use Drizzle, it never loads.
`react`, `drizzle-orm`, `lucide-react` and the two `@gentleduck/*` packages are
declared as optional peer dependencies. `vue` is not declared at all -
`createIamVueAccess(vue)` takes the Vue module you hand it, so the package never
resolves it itself.

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

A policy that throws is Indeterminate, never skipped. If it carries any deny
rule it evaluates to deny - a broken row that could have denied must not become
an allow, which is what skipping it did. An allow-only policy casts the
`defaultEffect` vote it would have cast had it evaluated. Either way the error
is routed to the `onPolicyError` hook.

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
cannot evict another tenant's cached entries.

`iamFlushSharedCaches()` is **not** a mitigation for this and needs no periodic
schedule: it clears only the process-global fallback caches used by direct
`evaluate()` / operator calls and by `explain()`. No `can()` path touches them.
Sharing one engine across tenants shares the per-instance caches it does not
clear, so give each tenant its own engine. See `SECURITY.md`.

### What are the built-in limits?

| Setting | Default | What it does |
|---------|---------|--------------|
| `cacheTTL` | 60s | cache lifetime |
| `maxCacheSize` | 1000 | subject cache entries |
| `adapterTimeoutMs` | 5000 | hard `AbortController` timeout per adapter call, reads and `engine.admin` writes alike |
| `hookTimeoutMs` | 5000 | bound on a promise a hook returns; `0` waits indefinitely |
| `maxPolicies` / `maxRoles` | 10,000 | load-time caps, fail closed when exceeded |
| role inheritance depth | 32 | how far the `inherits` walk descends. Not a cap on how many roles a catalog may hold |
| `MAX_CONDITION_DEPTH` | 10 | a group nested deeper throws `IamConditionGroupError`, which resolves to deny |
| `permissions()` batch | 1024 checks | refuses larger batches |

### What frameworks and databases work with it?

Server: Express, NestJS, Hono, Next.js, plus a generic adapter.
Client: React, Vue, vanilla JS.
Storage: Memory, File, Prisma, Drizzle (Postgres, MySQL, SQLite), Redis, HTTP.

The core is framework agnostic. All of the above are separate entry points.

### When is it *not* fast?

- **Cold start.** The first request after boot pays adapter load plus index
  build. `preload()` exists for exactly this: it moves that cost to boot, where
  a slow first call is nobody's request.
- **Heavy wildcard policies.** Rules containing `*` cannot be precomputed, and a
  single one anywhere in a policy disables the precomputed table for that whole
  policy. They are scanned from whichever wildcard bucket still has a literal
  side to key on, or from `wildcardBoth` when neither does. Prefer literal action
  and resource pairs where you can.
- **Regex conditions.** The `matches` operator is the most expensive of the 19
  operators, even with the compiled-regex cache. Use `eq`, `in`, or
  `starts_with` when they express the same thing.
- **Very large policy sets.** Index build cost is linear in rule count and paid
  on each cache refresh. 10,000 policies with a 60 second TTL means rebuilding
  every minute.
- **Development mode in production.** It allocates a decision object per policy
  per request. That is the point of the mode switch.

### How well tested is it?

See `docs/TEST-INVENTORY.md` for a catalog of every test file and what it
pins down. Run `bun run test` in the package for the authoritative counts -
quoting a number here only guarantees it goes stale. Use the script rather than
a bare `vitest run`: the script excludes the docker-backed e2e tier, which
`bun run test:e2e` runs on its own, and mixing the two reads as flakiness.
Beyond the unit suites there is mutation testing via Stryker, adapter
compliance suites shared across all six adapters, and benchmarks against five
competing libraries.

