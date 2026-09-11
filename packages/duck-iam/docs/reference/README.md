# Reference

Eleven pages covering `@gentleduck/iam` subsystem by subsystem, written against the
source rather than from the public API surface. Each one documents what the code does,
what it refuses, and where it will surprise you.

Start with [`core-engine.md`](./core-engine.md) if you are new — everything else hangs
off the engine's lifecycle.

## Core

| Page | Covers | Read it when |
| --- | --- | --- |
| [`core-engine.md`](./core-engine.md) | `src/core/engine`, `engine/compiled` | Constructing an engine, choosing config, understanding caches, compile triggers and every deny-vs-throw path |
| [`core-evaluate.md`](./core-evaluate.md) | `src/core/evaluate`, `conditions` | Writing conditions. Has the exhaustive 19-operator table with mismatched-type and absent-field columns |
| [`core-rbac.md`](./core-rbac.md) | `src/core/rbac`, `resolve`, `pending`, `batch` | Roles, inheritance, the two scope mechanisms, subject resolution, batch writes |
| [`core-schema.md`](./core-schema.md) | `src/core/schema`, `validate`, `types`, `config` | The type model, the 24 validation codes, and **where validation actually runs** |
| [`core-builder.md`](./core-builder.md) | `src/core/builder`, `explain` | Authoring policies with the DSL, and reading a decision trace |

## Integration

| Page | Covers | Read it when |
| --- | --- | --- |
| [`adapters-sql.md`](./adapters-sql.md) | `adapters/drizzle` (pg/mysql/sqlite), `adapters/prisma` | Writing your migration, or picking a dialect. Column-by-column schema plus a dialect divergence table |
| [`adapters-runtime.md`](./adapters-runtime.md) | `adapters/memory`, `file`, `http`, `redis`, `__compliance__` | Choosing a non-SQL store, or writing your own adapter. Has the full method × adapter contract |
| [`server.md`](./server.md) | `src/server/**` | Mounting on express, hono, Nest or Next. Admin endpoints and the full status-code table |
| [`client.md`](./client.md) | `src/client/**` | Hiding UI on permissions in React, Vue or vanilla. **Client checks are advisory — never authorization** |
| [`devtools.md`](./devtools.md) | `src/dt`, `src/dt/v2` | Inspecting evaluation inside your app. The two builds have deliberately opposite styling contracts |
| [`operations.md`](./operations.md) | `observability`, `invalidators`, `shared`, `test` | Running this across replicas. Metrics, the redis invalidator, and what a dropped invalidation costs |

## Companion documents

Design and internals, not duplicated in the pages above:

- [`../compiled-engine-explained.md`](../compiled-engine-explained.md) — wildcard buckets,
  role bitmasks and the `CompiledTable` layout, with diagrams and worked examples.
- [`../engine-rewrite.md`](../engine-rewrite.md) — design history, the 32-role cap, the two
  scope mechanisms, and the benchmark log.
- [`../TEST-INVENTORY.md`](../TEST-INVENTORY.md) — generated inventory of the suite.
- [`../../README.md`](../../README.md) — install, quick start, performance tables.
- [`../../SECURITY.md`](../../SECURITY.md) — disclosure policy.

## A note on how these are kept honest

Every `import { … } from '@gentleduck/iam…'` inside a code fence on these pages is checked
against the source barrels by `src/__tests__/docs-import-parity.test.ts`. A rename that
invalidates a snippet fails the suite rather than shipping. That test exists because an
earlier audit found nine documented symbols the package did not export — each one a
first-run failure for whoever copied it.

The check covers import statements. It cannot verify prose, so where these pages state a
behaviour they cite the file and line it came from.
