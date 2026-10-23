# benchmark/

Measures duck-auth's test coverage against better-auth's, feature by feature, so
"are we under-tested?" has an answer with numbers behind it instead of a feeling.

It does **not** cross-run the two suites. That was the original idea and it does
not work: a test binds to an API surface, not to a behaviour. better-auth's cases
call `auth.api.signInEmail(...)` and `auth.handler(new Request(...))`; duck-auth
ships no routes and no client (PR #288), and its cases reach into `auth.flows.*`,
store adapters and `expectedVersion` CAS semantics that have no better-auth
counterpart. Pointed at each other, both suites fail on imports and missing
methods — 100% red that says nothing about coverage. So this compares *scenarios*
per feature instead, which is the question the cross-run was a proxy for.

## Layout

| Path | What it is |
| --- | --- |
| `scripts/clusters.ts` | The feature vocabulary both suites are mapped onto, and the scope of each |
| `scripts/harvest.ts` | Walks a checkout, counts tests per file, assigns a cluster |
| `scripts/compare.ts` | Diffs two harvests, writes `out/GAP-TABLE.md` |
| `scripts/audit.ts` | Prints cluster membership, so a count can be checked rather than trusted |
| `scripts/run-suites.sh` | Actually runs both suites and records what executed |
| `out/` | Generated. Not hand-edited. |
| `FINDINGS.md` | The read on the numbers: what the gap is, and what to do |

## Refreshing it

```sh
# Clone better-auth, map both suites, diff them, rewrite the maps.
bun run coverage-gap                 # defaults to the measured tag, v1.7.2
bun run coverage-gap v1.8.0          # or re-measure against a newer one

# Check a number before quoting it: prints the files behind a cluster.
bun benchmark/scripts/audit.ts benchmark/out/better-auth.json oidc-op

# The authoritative counts, from runs rather than regexes.
bun run coverage-gap:run duck                    # our three tiers
bun run coverage-gap:run all /tmp/better-auth-src-v1.7.2
```

Running their suite needs their toolchain: `pnpm install` in the checkout first.
A full install pulls the docs site (next, prisma, workerd) and may time out on a
slow link; `pnpm install --filter "./packages/**" --filter "./test/**"` gets just
what the unit tier needs.

Note `benchmark` is already taken in this package — `bun run benchmark` is the
**bundle-size** benchmark in `scripts/benchmark.ts`, unrelated to this folder.

## Read the static counts as a lower bound

The static counter is a regex over source lines, and it undercounts, because a
test can be registered somewhere a regex cannot see it:

- **Shared suites.** duck-auth's store-contract matrices live in
  `src/test/store-compliance.ts` (111 cases) and `src/test/oidc-op-compliance.ts`
  (24). That is not a test file, so the three `compliance.test.ts` files that
  invoke it statically count **zero**. better-auth does the same thing from
  `packages/test-utils/src/adapter/suites/`, re-run once per dialect.
- **`it.each`.** One source line, many cases.

Measured on duck-auth: static says 3229 unit tests, a real run executes **4308** —
a 25% undercount. So the per-cluster table shows *shape*, and only
`run-suites.sh` output should be quoted as a count.

`vitest list` is not a way around this. It reports **0 tests** for
`src/adapters/memory/__tests__/compliance.test.ts`, a file `vitest run` executes
110 tests from. Do not trust it here.

## Scope is the honest column

A zero in the table is one of three different things, and `clusters.ts` records
which:

- `shared` — both implement it, so a count difference is a coverage difference.
- `ba-only-gap` — better-auth has it, we do not, and arguably should.
- `ba-only-by-design` — we deliberately do not have it (no client bindings, no
  route layer, no billing). A zero here is a boundary, not a hole.
- `duck-only` — we have it and better-auth has no counterpart.

Collapsing those into one "better-auth has more tests" number is how this
exercise would end up lying in our favour or against it.

## On the third-party checkout

The better-auth clone is downloaded, untrusted source. Everything here only reads
and greps it; nothing imports from it into our test process. `run-suites.sh` runs
their suite with its own toolchain, in its own directory, and keeps it out of
ours. Their `e2e/adapter` tier additionally needs the docker-compose stack in
their checkout (postgres ×4, mysql ×3, mssql, mongo, redis on fixed host ports);
that is not started for you.
