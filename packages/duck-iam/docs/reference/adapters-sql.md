# SQL adapters: Drizzle and Prisma

Two adapters back the engine with a relational database: `IamDrizzleAdapter`,
one implementation covering Postgres, MySQL and SQLite, and `IamPrismaAdapter`,
which talks to a Prisma client structurally without importing one. This
document gives the tables they expect column by column, the exact wiring for
each dialect, every place the three SQL dialects diverge in behaviour rather
than syntax, and the transaction contract both implement through `withClient`.
The shared method contract every adapter is held to lives in
[`adapters-runtime.md`](./adapters-runtime.md) and is not repeated here.

---

## 1. Entry points

| Import | Exports |
| --- | --- |
| `@gentleduck/iam/adapters/drizzle` | `IamDrizzleAdapter`, `iamDrizzleAdapter`, `createIamDrizzleAdapter`, namespace `IamDrizzle` |
| `@gentleduck/iam/adapters/drizzle/pg` | `iamPolicies`, `iamRoles`, `iamAssignments`, `iamSubjectAttrs`, `combineAlgorithm`, type namespace `Pg` |
| `@gentleduck/iam/adapters/drizzle/mysql` | `iamPolicies`, `iamRoles`, `iamAssignments`, `iamSubjectAttrs`, type namespace `Mysql` |
| `@gentleduck/iam/adapters/drizzle/sqlite` | `iamPolicies`, `iamRoles`, `iamAssignments`, `iamSubjectAttrs`, `IAM_COMBINE_ALGORITHMS`, type namespace `Sqlite` |
| `@gentleduck/iam/adapters/prisma` | `IamPrismaAdapter`, `iamPrismaAdapter`, namespace `IamPrisma` |

The dialect subpaths export **schema only**. The adapter class is dialect-neutral
and lives at `adapters/drizzle`; which dialect you are on is a runtime config
field, not a different class. A construction therefore names two imports:

```ts
import { IamDrizzleAdapter } from '@gentleduck/iam/adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '@gentleduck/iam/adapters/drizzle/pg'
```

The four table exports have the same names in all three subpaths, so switching
dialect is a one-line change to the import path plus the config fields in §4.

Prisma ships no schema module — it ships `schema.prisma` as source you copy
(`src/adapters/prisma/schema.prisma`). See §8.

---

## 2. The tables

Four tables. Names are fixed only by the schema modules; the adapter reads
whatever table objects you hand it in `config.tables`, so a consumer with their
own naming can point it at their own tables as long as the *column property
names* match. Those property names are the real contract:

```
policies:    id name description version algorithm rules targets createdBy updatedBy createdAt updatedAt
roles:       id name description permissions inherits scope metadata createdBy updatedBy createdAt updatedAt
assignments: id subjectId roleId scope startsAt expiresAt attributes createdBy updatedBy createdAt updatedAt
attrs:       subjectId data createdBy updatedBy createdAt updatedAt
```

`schema-parity.test.ts` (`src/adapters/drizzle/__tests__/schema-parity.test.ts`)
holds the three dialect modules to one shape: same columns, same
NOT-NULL-without-default set, same named indexes, same CHECKs, same foreign
keys. Anything a dialect owns alone must be listed in that file's `DIALECT_ONLY`
allow-list with the reason the other two cannot express it, and a second test
asserts every allow-list entry actually exists. The same file also diffs
`src/test/pg-e2e-schema.sql` against `pg.schema.ts`, because a hand-kept SQL
mirror that nothing compares is a mirror that drifts.

### 2.1 `iam_policies`

Stored ABAC policies. `src/adapters/drizzle/pg/pg.schema.ts:40`.

| Column | Postgres | MySQL | SQLite | Null | Default |
| --- | --- | --- | --- | --- | --- |
| `id` | `text` | `varchar(191)` | `text` | no | — (PK) |
| `name` | `text` | `varchar(191)` | `text` | no | — |
| `description` | `text` | `varchar(1024)` | `text` | yes | — |
| `version` | `integer` | `int` | `integer` | no | `1` |
| `algorithm` | enum `iam_combine_algorithm` | `enum(...)` | `text` + CHECK | no | `'deny-overrides'` |
| `rules` | `jsonb` | `json` | `text` | no | — |
| `targets` | `jsonb` | `json` | `text` | yes | — |
| `created_by` | `text` | `varchar(191)` | `text` | yes | — |
| `updated_by` | `text` | `varchar(191)` | `text` | yes | — |
| `created_at` | `timestamptz` | `datetime(3)` | `integer` (ms) | no | now |
| `updated_at` | `timestamptz` | `datetime(3)` | `integer` (ms) | no | now, `$onUpdate` |

Constraints: `pk_iam_policies` on `id`; `ch_iam_policies_name_not_blank`;
`ch_iam_policies_version_positive` (`version >= 1`). Postgres alone carries
`idx_iam_policies_rules_gin`, a GIN index for containment search over `rules`.
SQLite alone carries `ch_iam_policies_algorithm_valid`, because it has no enum
type — the other two encode the closed set in the column type.

**There is deliberately no unique index on `name`.** The schema comment says why
(`pg.schema.ts:60`): nothing in the engine resolves a policy by name, `id` is
the key everywhere, so uniqueness bought a label nobody reads at the cost of
making Postgres the one adapter where a second policy with a duplicate name is
impossible. "Two adapters disagreeing about whether a write succeeds is the
failure this schema must not have." The same reasoning removes the
`(name, scope)` unique index from `iam_roles`.

### 2.2 `iam_roles`

`pg.schema.ts:73`.

| Column | Postgres | MySQL | SQLite | Null | Default |
| --- | --- | --- | --- | --- | --- |
| `id` | `text` | `varchar(191)` | `text` | no | — (PK) |
| `name` | `text` | `varchar(191)` | `text` | no | — |
| `description` | `text` | `varchar(1024)` | `text` | yes | — |
| `permissions` | `jsonb` | `json` | `text` | no | — |
| `inherits` | `jsonb` | `json` | `text` | no | `'[]'` |
| `scope` | `text` | `varchar(191)` | `text` | yes | — |
| `metadata` | `jsonb` | `json` | `text` | yes | — |
| `created_by` / `updated_by` | `text` | `varchar(191)` | `text` | yes | — |
| `created_at` / `updated_at` | `timestamptz` | `datetime(3)` | `integer` (ms) | no | now |

Constraints: `pk_iam_roles`; `idx_iam_roles_scope` (partial,
`WHERE scope IS NOT NULL`, on Postgres and SQLite; unfiltered on MySQL, which
has no partial indexes); `ch_iam_roles_name_not_blank`;
`ch_iam_roles_scope_not_blank` (NULL or non-whitespace). Postgres alone carries
`idx_iam_roles_permissions_gin`.

`inherits` needs its default spelled three ways: `sql`'[]'::jsonb`` on Postgres,
`sql`('[]')`` on MySQL (an expression default is the only form MySQL accepts for
a JSON column, 8.0.13+), and the literal `'[]'` on SQLite. The MySQL comment at
`mysql.schema.ts:76` records why the expression form matters: without it,
`inherits` was the one column an insert had to supply on MySQL and nowhere else
— exactly the class of divergence the parity test's "requires the same columns
on insert" clause now catches.

### 2.3 `iam_assignments`

Subject-to-role grants. `pg.schema.ts:142`. A NULL `scope` is a global
(unscoped) grant; NULL `starts_at`/`expires_at` means unbounded in that
direction, so a row with both NULL behaves exactly as every assignment did
before those columns existed.

| Column | Postgres | MySQL | SQLite | Null | Default |
| --- | --- | --- | --- | --- | --- |
| `id` | `text` | `varchar(191)` | `text` | no | uuidv7 (client-side `$defaultFn`) |
| `subject_id` | `text` | `varchar(191)` | `text` | no | — |
| `role_id` | `text` | `varchar(191)` | `text` | no | — |
| `scope` | `text` | `varchar(191)` | `text` | yes | — |
| `starts_at` | `timestamptz` (custom type) | `datetime(3)` | `integer` (ms) | yes | — |
| `expires_at` | `timestamptz` (custom type) | `datetime(3)` | `integer` (ms) | yes | — |
| `attributes` | `jsonb` | `json` | `text` | yes | — |
| `created_by` / `updated_by` | `text` | `varchar(191)` | `text` | yes | — |
| `created_at` / `updated_at` | `timestamptz` | `datetime(3)` | `integer` (ms) | no | now |

Constraints on every dialect:

- `pk_iam_assignments` on `id`.
- `fk_iam_assignments_role` → `iam_roles(id)`, `ON DELETE CASCADE`. This is what
  makes `assignRole` refuse an unknown role, and it does work no application
  check can: it stops `deleteRole` leaving orphan grants that a role later
  recreated under the same id would resurrect
  (`src/shared/assignment-target.ts`). The constraint cannot reach the other
  place a role id is written down — `iam_roles.inherits` is a JSON array, not a
  referencing column — so `deleteRole` sweeps those edges itself
  (`iamRoleWithoutInherit`), on every adapter.
- `uq_iam_assignments_subject_role_scope` — see the NULL note below.
- `idx_iam_assignments_subject`, `idx_iam_assignments_role`,
  `idx_iam_assignments_subject_scope`, `idx_iam_assignments_expires_at`.
- `ch_iam_assignments_subject_not_blank`, `ch_iam_assignments_scope_not_blank`,
  `ch_iam_assignments_starts_before_expires`
  (`starts_at IS NULL OR expires_at IS NULL OR starts_at < expires_at`).

**The unique index has to collapse NULLs, and the three dialects spell that
differently.** SQL unique indexes treat NULLs as distinct, so a plain
`UNIQUE (subject_id, role_id, scope)` does not stop two identical *unscoped*
grants. Postgres uses `NULLS NOT DISTINCT` (`.nullsNotDistinct()`,
`pg.schema.ts:169`); MySQL and SQLite have no such clause and index the
coalesced value instead — `(coalesce(scope, ''))`
(`mysql.schema.ts:132`, `sqlite.schema.ts:130`). Both spellings mean the same
thing, and both are load-bearing: the adapter's insert-or-skip depends on the
database catching the duplicate, not on a read that raced.

`idx_iam_assignments_subject_scope` and `idx_iam_assignments_expires_at` are
partial (`WHERE ... IS NOT NULL`) on Postgres and SQLite and unfiltered on
MySQL, which has no partial indexes. The comment at `mysql.schema.ts:136` says
the composite is still needed there: the scoped-subject lookup wants it rather
than a subject scan plus a filter.

### 2.4 `iam_subject_attrs`

One row per subject, holding the ABAC attribute bag. `pg.schema.ts:184`.

| Column | Postgres | MySQL | SQLite | Null | Default |
| --- | --- | --- | --- | --- | --- |
| `subject_id` | `text` | `varchar(191)` | `text` | no | — (PK) |
| `data` | `jsonb` | `json` | `text` | **no** | — |
| `created_by` / `updated_by` | `text` | `varchar(191)` | `text` | yes | — |
| `created_at` / `updated_at` | `timestamptz` | `datetime(3)` | `integer` (ms) | no | now |

Constraints: `pk_iam_subject_attrs` on `subject_id`;
`ch_iam_subject_attrs_subject_not_blank`. No index beyond the primary key — every
read of this table is a lookup by `subject_id`.

`data` being `NOT NULL` on all three is what licenses the read path to treat a
`null` as corruption rather than as "no attributes" — see §6.3.

### 2.5 Postgres DDL, verbatim

`src/test/pg-e2e-schema.sql` is the mirror the parity test checks against
`pg.schema.ts`, and it is a runnable migration:

```sql
DO $$ BEGIN
  CREATE TYPE iam_combine_algorithm AS ENUM ('deny-overrides', 'allow-overrides', 'first-match', 'highest-priority');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS iam_assignments (
  id         text NOT NULL,
  subject_id text NOT NULL,
  role_id    text NOT NULL,
  scope      text,
  starts_at  timestamptz,
  expires_at timestamptz,
  attributes jsonb,
  created_by text,
  updated_by text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT pk_iam_assignments PRIMARY KEY (id),
  CONSTRAINT fk_iam_assignments_role FOREIGN KEY (role_id) REFERENCES iam_roles (id) ON DELETE CASCADE,
  CONSTRAINT uq_iam_assignments_subject_role_scope UNIQUE NULLS NOT DISTINCT (subject_id, role_id, scope),
  CONSTRAINT ch_iam_assignments_subject_not_blank CHECK (subject_id ~ '[^[:space:]]'),
  CONSTRAINT ch_iam_assignments_scope_not_blank CHECK (scope IS NULL OR scope ~ '[^[:space:]]'),
  CONSTRAINT ch_iam_assignments_starts_before_expires
    CHECK (starts_at IS NULL OR expires_at IS NULL OR starts_at < expires_at)
);
```

For MySQL and SQLite, point `drizzle-kit generate` at the shipped schema module
rather than hand-writing DDL — the `coalesce` unique index and the MySQL
expression default for `inherits` are easy to get wrong by hand.

---

## 3. Setup

### 3.1 Postgres

```ts
import { and, eq, isNull, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { IamDrizzleAdapter } from '@gentleduck/iam/adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '@gentleduck/iam/adapters/drizzle/pg'
import { IamEngine } from '@gentleduck/iam'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

const adapter = new IamDrizzleAdapter<Action, Resource, Role, Scope>({
  db: drizzle(pool),
  tables: { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles },
  ops: { and, eq, isNull, or },
  // dialect defaults to 'pg', json defaults to 'native' - both correct here
  onPolicyError: (err, ctx) => logger.error({ adapter: ctx.adapter, rowId: ctx.rowId }, err.message),
})

const engine = new IamEngine({ adapter })
```

`ops` takes drizzle's own operators, passed straight through. That has been true
only since commit `1e67893b`: `ops.eq` used to be declared
`(col: unknown, val: unknown) => unknown`, and under `strictFunctionTypes` an
`unknown` *parameter* is the narrowest thing a caller can satisfy, not the
widest — so drizzle's real `eq`, whose parameters are `Column`/`SQLWrapper`, was
not assignable to it. The wiring the adapter's own `@example` showed did not
compile against the library it adapts, and every caller wrote a re-widening
wrapper with two casts in it. `ops.eq` is now `BinaryOperator` and `ops.isNull`
is `(col: SQLWrapper) => SQL`, both drizzle's types.
`src/adapters/drizzle/__tests__/ops-wiring-types.test.ts` is a `tsc`-checked
type test that keeps it that way; a regression there is a compile error in that
file, which is where a caller would hit it too.

### 3.2 MySQL

```ts
import { and, eq, isNull, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/mysql2'
import mysql from 'mysql2/promise'
import { IamDrizzleAdapter, type IamDrizzle } from '@gentleduck/iam/adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '@gentleduck/iam/adapters/drizzle/mysql'

const pool = mysql.createPool(process.env.DATABASE_URL!)

const adapter = new IamDrizzleAdapter<Action, Resource, Role, Scope, IamDrizzle.AnyDrizzleDb, 'mysql'>({
  db: drizzle(pool),
  dialect: 'mysql',            // REQUIRED - see below
  tables: { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles },
  ops: { and, eq, isNull, or },
})
```

`dialect` defaults to `'pg'` (`index.ts:319`), and nothing inspects `db` to
detect the dialect for you. Omitting `dialect: 'mysql'` sends
`onConflictDoUpdate()` and `onConflictDoNothing()` to a MySQL insert builder that
has neither, so every method that inserts fails at runtime: `savePolicy`,
`saveRole`, `setSubjectAttributes`, `assignRole` and `assignRoleMany` (which also
reaches for a `returning()` MySQL has not got). `deletePolicy`, `deleteRole`,
`revokeRole`, `revokeRoleMany` and `updateAssignmentScope` build no conflict
clause and keep working, so the misconfiguration surfaces as "writes fail,
revokes succeed" rather than as a dead adapter. The sixth type parameter
(`'mysql'`) only narrows `IConfig`'s table types; the branch the adapter takes is
the runtime `dialect` field.

**MySQL writes are not atomic upserts.** `savePolicy`, `saveRole` and
`setSubjectAttributes` read the row first and then branch to an INSERT or an
UPDATE, because MySQL's `ON DUPLICATE KEY UPDATE` fires on *any* unique index
and could overwrite a different row. Two writers saving the same id at once can
therefore both read "absent", and the one that loses the race fails with the
driver's duplicate-key error while the other's row stands. Postgres and SQLite
issue one `ON CONFLICT` statement and both callers succeed. Retry a write that
fails this way; the row it wanted is already there. Measured on a real engine
for both chains in `drizzle-sqlite-real-engine.test.ts`.

### 3.3 SQLite

```ts
import { and, eq, isNull, or } from 'drizzle-orm'
import Database from 'better-sqlite3'
import { drizzle } from 'drizzle-orm/better-sqlite3'
import { IamDrizzleAdapter, type IamDrizzle } from '@gentleduck/iam/adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '@gentleduck/iam/adapters/drizzle/sqlite'

const adapter = new IamDrizzleAdapter<Action, Resource, Role, Scope, IamDrizzle.AnyDrizzleDb, 'sqlite'>({
  db: drizzle(new Database('iam.db')),
  dialect: 'sqlite',
  json: 'string',              // REQUIRED - every payload column is TEXT
  tables: { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles },
  ops: { and, eq, isNull, or },
})
```

`json: 'string'` is not optional on the shipped SQLite schema. Its `rules`,
`targets`, `permissions`, `inherits`, `metadata`, `attributes` and `data`
columns are all TEXT typed `$type<string>()`, and `'native'` mode hands the
driver a live object. The requirement is stated in the schema docblock
(`sqlite.schema.ts:8`) and checked nowhere: the constructor (`index.ts:318`)
reads `config.json ?? 'native'` without looking at `dialect` or at the tables,
`IConfig`'s `json` field is independent of its `TType` parameter, and the
`tables` type is `SQLiteTableWithColumns<any>`, whose columns are `any`. No
test in the suite pins the combination either. The object reaches the driver
unexamined, so whatever your SQLite driver does with a non-scalar bind parameter
is the whole of the diagnosis you get.

`dialect: 'sqlite'` and `dialect: 'pg'` take identical code paths today: the
four runtime branches in the adapter are all `!== 'mysql'` /
`=== 'mysql'` tests (`index.ts:371`, `index.ts:389`, `index.ts:887`,
`index.ts:928`). Pass `'sqlite'` anyway; it is what makes the config type match
the tables and it is the field a future divergence would branch on.

### 3.4 Prisma

```ts
import { PrismaClient } from '@prisma/client'
import { IamPrismaAdapter } from '@gentleduck/iam/adapters/prisma'

const prisma = new PrismaClient()
const adapter = new IamPrismaAdapter<Action, Resource, Role, Scope>(prisma)
```

One argument, no options object. That is itself load-bearing: the adapter has
nowhere to wire an `onPolicyError`, which is why every corrupt-row report it
makes goes to `console.warn` (§8.3).

---

## 4. `IamDrizzle.IConfig`

`src/adapters/drizzle/index.ts:32`.

| Field | Type | Default | Effect |
| --- | --- | --- | --- |
| `db` | `TDb extends AnyDrizzleDb` | — | Anything with `select`/`insert`/`update`/`delete`. A structural interface, not a union, so `db.select()` type-checks on a generic `TDb`. |
| `tables` | `{ policies, roles, assignments, attrs }` | — | Drizzle table objects. Column *property* names are the contract (§2). |
| `ops.eq` | `BinaryOperator` | — | Required. |
| `ops.and` | `(...c) => SQL \| undefined` | — | Required. |
| `ops.isNull` | `(col: SQLWrapper) => SQL` | absent | Optional. Gates `updateAssignmentScope` entirely. |
| `ops.or` | `(...c) => SQL \| undefined` | absent | Optional. Collapses `revokeRoleMany` into one `DELETE`. |
| `dialect` | `'pg' \| 'mysql' \| 'sqlite'` | `'pg'` | Only `'mysql'` changes behaviour. |
| `json` | `'native' \| 'string'` | `'native'` | Write encoding. The read path accepts both, so switching is migration-safe. |
| `onPolicyError` | `(err, { adapter, rowId }) => void` | `console.warn` | Fires for every malformed row, before any throw. |

### The two optional operators are gates, not decorations

Both omissions are correct but degraded, and silently so, which is why the
adapter warns at construction (`warnMissingOps`, `index.ts:188`):

```
[@gentleduck/iam:drizzle] running on a degraded path; ops is missing
`isNull` - updateAssignmentScope() cannot match an unscoped (NULL) assignment in place and falls back to revoke + assign;
`or` - revokeRoleMany() issues one DELETE per row instead of one statement.
Pass them through from drizzle-orm: `ops: { eq, and, isNull, or }`.
```

Neither can be derived. `eq(col, null)` is not `IS NULL` in SQL, and there is no
way to synthesise an `OR` builder from `eq` and `and`. Without `isNull`,
`updateAssignmentScope` returns `false` on its first line (`index.ts:961`) and
the engine falls back to revoke + assign: two writes, and a window where the
subject holds nothing.

The warning set is **module-level**, not per-instance
(`warnedMissingOps`, `index.ts:155`). `withClient` re-constructs the adapter for
every transaction, so a per-instance flag would turn one misconfiguration into
one warning per transaction — which is how a startup diagnostic becomes log
noise operators filter out.

Note that the compliance mocks in `drizzle.test.ts` supply all four operators
deliberately. Omitting them there did not make those paths fail, it made them
never run, so the whole matrix certified the degraded branch while the shipped
one was dark outside the Docker e2e tier.

---

## 5. Dialect divergence

### 5.1 The comparison table

| Concern | Postgres | MySQL | SQLite | Adapter behaviour |
| --- | --- | --- | --- | --- |
| JSON columns | `jsonb` | `json` | `TEXT` | `json: 'native'` for pg/mysql, `json: 'string'` for sqlite. Read path accepts both shapes on all three. |
| Upsert | `onConflictDoUpdate({ target })` | select-then-branch | `onConflictDoUpdate({ target })` | `_upsert`, `index.ts:361` |
| Insert-or-skip | `.values().onConflictDoNothing()` | `.ignore().values()` | `.values().onConflictDoNothing()` | `_insertOrSkip`, `index.ts:388` |
| `RETURNING` | yes | **no** | yes | `assignRoleMany` / `revokeRoleMany` return `null` on MySQL |
| Unique over NULL scope | `NULLS NOT DISTINCT` | `(coalesce(scope,''))` index | `coalesce(scope,'')` index | schema, not adapter |
| Partial indexes | yes | **no** | yes | MySQL indexes are unfiltered |
| Enum for `algorithm` | `pgEnum` | `mysqlEnum` | `text` + CHECK | SQLite-only CHECK, allow-listed in the parity test |
| GIN on JSON | yes | no | no | pg-only indexes, allow-listed |
| CHECK constraints | enforced | 8.0.16+ only | enforced | below 8.0.16 MySQL parses and ignores them |
| Timestamp precision | `timestamptz` (µs) | `datetime(3)` (ms) | `integer` epoch ms | see §5.4 |
| `infinity` timestamps | yes | no | no | custom column type, pg only |
| Identifier length | unbounded `text` | `varchar(191)` | unbounded `text` | see §5.5 |

### 5.2 Why MySQL upserts by hand

MySQL has no `ON CONFLICT`, and its `onDuplicateKeyUpdate` fires on *any*
unique-index violation rather than only the one you named. A blanket
`onDuplicateKeyUpdate` would therefore let a row with a fresh `id` that
collides on some *other* unique index silently overwrite that unrelated row —
id included — where the `target`-scoped `onConflictDoUpdate` on pg/sqlite
throws, because the conflict is not on the column it was told to expect. So on
MySQL the adapter probes by `target` first and issues a plain `UPDATE` or a
plain `INSERT` (`index.ts:371-380`), and a genuine secondary-index collision
surfaces as a thrown duplicate-entry error, matching the fail-closed behaviour
of the other two.

On the shipped schemas that collision cannot arise: `iam_policies` and
`iam_roles` carry a primary key and no other unique index (§2.1). What the
branch protects today is a consumer table that declares a secondary unique index
of its own, which `config.tables` allows — and the shipped schemas regaining one,
which would bring the silent-overwrite behaviour back with no change to the
adapter. The `_upsert` docblock (`index.ts:339`) states both.

Consequence for the caller: the MySQL upsert is a read-then-write, so two
concurrent `saveRole` calls for the same new id can both see nothing and both
insert. The primary key rejects the loser — loudly, which is the right failure —
but it is a failure a pg/sqlite deployment does not see.

### 5.3 `RETURNING`, and what `null` means

`assignRoleMany` and `revokeRoleMany` report *which input rows this statement
actually changed*, by reading the rows back off the same write via `RETURNING`
and matching them against the request with `creditWrites`
(`src/core/batch/batch.ts:49`). MySQL has no `RETURNING` on either statement, so
both methods return `null` there.

`null` is not "nothing was written". Both suites pin this
(`drizzle.test.ts`, `mysql dialect` block): the grants land, and `null` says the
driver cannot name which of them were new, so the engine leaves `changed` off
the outcome rather than guessing. Finding out would cost a second round trip for
an answer nobody asked for.

Crediting is per-statement, so two batch rows asking for the same grant credit
one index, and a subsuming revoke (a row with no `scope`, which revokes the role
everywhere) credits itself rather than the narrower row it already covers.

### 5.4 Timestamps

Three storage shapes reach `epochMs` (`index.ts:226`), which normalises them:
`Date` → `getTime()`, string → `new Date(...)`, and a non-finite number passed
through as itself. `_isActive` (`index.ts:560`) then answers
`[startsAt, expiresAt)` — inclusive lower bound, exclusive upper, pinned to the
millisecond by the fake-clock cases in
`drizzle-assignment-expiry-attributes.test.ts`.

The precision differences are real but rarely load-bearing: `datetime(3)` and
SQLite's epoch-ms columns both hold milliseconds, and the engine compares in
milliseconds. Postgres's microseconds round-trip fine and are simply finer than
anything the adapter reads.

**`infinity` is the divergence that matters.** Postgres spells "never expires"
as `expires_at = 'infinity'`, and node-postgres parses it to the JS number, not
a `Date`. Drizzle's own `timestamp()` maps every driver value through
`new Date(...)`, and `new Date('infinity')` is an Invalid Date —
indistinguishable from a genuinely corrupt column, which the adapter reads as
"bound unreadable, row inactive". A grant written to mean *always* read back as
*expired*: a wrong DENY on the exact value an operator writes to prevent one. So
the pg schema declares a `customType` (`pg.schema.ts:117`) that keeps
`±Infinity` as numbers; the SQL type is unchanged, so this is not a migration.
The comparisons then give all four spellings the right answer with no special
case: `now < -Infinity` is false, so a `-infinity` start has always begun;
`now >= Infinity` is false, so an `infinity` expiry never lapses.

`_isActive` uses `Number.isNaN`, not `!Number.isFinite`, for exactly this reason
(`index.ts:567`): only an *unreadable* bound makes a row inactive on sight.
`±Infinity` is readable.

MySQL and SQLite have no infinity value. On those dialects, "never expires" is
`NULL`, which the same code already handles.

### 5.5 What a MySQL deployment must do differently

- Every identifier column is `varchar(191)` — a subject id, role id, policy id
  or scope longer than 191 characters is a write error on MySQL and fine on the
  other two. 191 is the usual `utf8mb4` index-length ceiling; widen it only if
  your index limits allow.
- `description` is `varchar(1024)`, where pg and sqlite are unbounded text.
- On MySQL below 8.0.16, every `ch_*` CHECK is parsed and ignored, so the
  database stores what it would otherwise reject. Two of the three are still
  refused by the adapter on every dialect: `iamAssertAssignableScope` rejects a
  blank scope and `iamAssertValidAssignWindow` rejects `startsAt >= expiresAt`.
  A blank *subject id* has no adapter-side guard, so on MySQL below 8.0.16
  nothing rejects one. A direct SQL write or a migration import bypasses all
  three.
- `assignRoleMany` / `revokeRoleMany` return `null`, so the engine reports
  `ok: true` per row with no `changed` field.
- The upsert races as described in §5.2.

### 5.6 What a SQLite deployment must do differently

- Set `json: 'string'`. Nothing checks it for you.
- The `algorithm` column is plain `text` with a CHECK, so a hand-written
  migration that omits `ch_iam_policies_algorithm_valid` will store an invalid
  algorithm. It is caught on read — `_safeParsePolicy` refuses the row and the
  read throws — which is a much more expensive place to find out.

---

## 6. The read path

### 6.1 A bad policy row is refused; a bad role row is dropped

This asymmetry is deliberate, it is shared by every adapter in the package, and
it is the single most important thing to know about operating these tables.

```ts
// index.ts:450 - _safeParsePolicy
this._reportPolicyError(detail, row.id)
throw iamUnreadablePolicy('drizzle', row.id, detail.message)
```

```
[@gentleduck/iam:drizzle] policy "p7" cannot be read and will not be skipped -
a dropped policy may be the one that denies. Repair or delete the row. (...)
```

One unreadable policy row therefore fails **every** read of the policy table and
the engine denies everything until it is repaired. That cost is the point.
`src/shared/rows.ts:120` gives the reasoning: a dropped policy may have been the
rule saying NO, and under `policyCombine: 'and'` even an allow-only policy votes
deny when none of its rules match — so there is no subset of policies an adapter
can safely drop without knowing a combine mode it cannot see.

A role row is skipped instead, and the rest are returned, because role
permissions are allow-only: losing one can only cost a subject a grant.
`_safeParseRole` (`index.ts:474`) reports through `onPolicyError` and returns
`null`.

`getPolicy` on a corrupt row throws rather than returning `null`. `null` is the
answer for a row that is not there, and a corrupt row must not be able to
impersonate a deleted one.

Both halves of the parse are covered: a JSON column that will not parse, and a
column that parses into the wrong shape. The second is the nastier one —
`rules: '[]'` stored as a raw string reads loosely like a policy with no rules,
which under `deny-overrides` is a policy that denies nothing.

### 6.2 Row shape: absent keys, not `undefined` ones

`_safeParseRole` omits `description`, `inherits`, `scope` and `metadata` rather
than setting them to `undefined`:

```ts
...(row.description === null || row.description === undefined ? {} : { description: row.description }),
...(Array.isArray(inherits) && inherits.length === 0 ? {} : { inherits }),
```

A key holding `undefined` is still a key: `Object.keys` lists it,
`JSON.stringify` drops it, and `toEqual` ignores it — so "does this role have a
description" got three different answers depending which one the consumer asked,
and a role saved as `{id, name, permissions}` read back from Postgres with seven
keys and from memory with three. An empty `inherits` is dropped because that is
what the column's `'[]'` default produces for a role saved without one. Anything
else, *including a value that is not an array*, is passed straight to
`parseRoleRow` to refuse — a corrupt column must not be normalised away.

Prisma's `toRole` (`prisma/index.ts:666`) applies the identical rule, and
`prisma.test.ts` pins the round trip: a role saved as three keys comes back as
exactly those three.

### 6.3 Subject attributes: corruption is not emptiness

`getSubjectAttributes` returns `{}` only when there is **no row**. A row that
exists and holds anything other than a JSON object of scalar values throws:

```
[@gentleduck/iam:drizzle] corrupted attributes for "u1" (not a JSON object)
[@gentleduck/iam:drizzle] corrupted attributes for "u1" (JSON parse failed)
```

There is deliberately no `data === null → {}` short circuit (`index.ts:1016`).
`data` is `NOT NULL` in all three shipped schemas, so a row that exists cannot
carry an absent value — a `null` arriving here is `'null'::jsonb`, a stored
value, and the shape an import or a hand-written migration produces from a
missing field. Answering `{}` for it read as "this subject has no attributes"
and silently retired every deny rule that tests one; Prisma's adapter threw on
the identical row. Arrays, numbers, booleans and strings are refused the same
way. The error message never echoes the column value — that is pinned by a test,
because these strings reach operator logs.

`setSubjectAttributes` reads-merges-writes, and it deliberately *recovers* from
a corrupt existing bag: the read is wrapped, a failure is reported through
`onPolicyError` (drizzle, `index.ts:1066`) or `console.warn` (prisma,
`prisma/index.ts:613`), and the write proceeds with `existing = {}`. The
alternative is an operator locked out of repairing the row by the row they are
repairing.

On both SQL adapters that `catch` is **unconditional**, so it also takes a read
that failed for an unrelated reason — a dropped connection — and the write then
replaces the subject's whole bag with the keys in this call. Wire the handler and
treat a report from here as a possibly-truncated bag rather than a logged
curiosity. The redis adapter narrows the same `catch` to the corrupt-blob case
and rethrows a driver failure ([`adapters-runtime.md`](./adapters-runtime.md)
§6.4); drizzle and prisma do not.

Both adapters run `iamAssertAttributesParam` first, so a non-object `attrs`
throws `must be a plain object` before anything is written. Before that guard
existed, `setSubjectAttributes(id, 'abc')` spread into per-character keys and
wrote `{0:'a',1:'b',2:'c'}` on the two SQL adapters while the other four threw.

### 6.4 Per-grant assignment attributes

`iam_assignments.attributes` is surfaced onto each `IScopedRole` from
`getSubjectScopedRoles`. Corruption there drops **just the field**, reported and
not thrown (`_parseAssignmentAttributes`, `index.ts:579`) — unlike subject
attributes, a bad value here should not fail the whole role list. A clean row
for the same subject is unaffected. The key is omitted entirely when the column
is NULL, and an empty object `{}` is surfaced as `{}` rather than treated as
absent.

`row.id ?? row.subjectId` is used as the report's `rowId`, because MySQL's `id`
has no adapter-side default and so is nullable in `AssignmentRow`.

---

## 7. Writes

### 7.1 Guards that run before any SQL

| Guard | Applies to | Refuses |
| --- | --- | --- |
| `iamAssertSavablePolicy` / `iamAssertSavableRole` | `savePolicy`, `saveRole` | anything the read path would later drop |
| `iamAssertAssignableScope` | `assignRole`, `revokeRole`, `updateAssignmentScope` (both ends), both batch methods | `''` always; `'*'` on a grant (not on a lookup) |
| `iamAssertValidAssignWindow` | drizzle `assignRole`, `assignRoleMany` | `startsAt >= expiresAt`, and any `Invalid Date` |
| `iamAssertNoAssignOptions` | **prisma** `assignRole` | `startsAt`, `expiresAt`, `attributes` |
| `iamAssertAttributesParam` | `setSubjectAttributes` | a non-plain-object payload, and any payload carrying a `__proto__` key |

`''` is refused because five of the six adapters accepted it and produced five
different outcomes. `'*'` is refused on a grant because a scoped assignment is
matched *literally* — `assignRole(u, r, '*')` beside a role declared
`scope: '*'` is the obvious move and does not mean the same thing; the row lands,
the call reports success, and the grant answers only a request whose own scope is
the string `"*"`. Lookups are exempt so an operator can still delete `'*'` rows
written before the guard existed.

`updateAssignmentScope` was the one write path this guard did not cover, on all
four adapters that implement it. It took `''` and `'*'` as the destination and
answered `true`, so the operator was told the grant had moved while it sat under
a scope no request can name — a silently dead grant, and a row the adapter's own
`assignRole` refuses. The engine's admin layer already guarded both ends, so the
hole was reachable only by driving an adapter directly, which the compliance
suite and every published adapter constructor do.

Batch guards run over the **whole** batch before the first write. A batch with
one bad row is refused entirely rather than half-applied — a partially-applied
revocation is the worse of the two outcomes.

### 7.2 `assignRole`

Insert-or-skip. A duplicate `(subject, role, scope)` is a no-op, matching every
other adapter. An unknown `roleId` is refused by `fk_iam_assignments_role` and
translated: `_refusingUnknownRole` (`index.ts:819`) catches the driver error and
rethrows

```
[@gentleduck/iam:drizzle] cannot assign a role that is not stored; save the role before granting it
```

with the driver error kept as `cause`. The database is the check here — checking
first would leave a window where the role is deleted before the insert lands —
but drizzle buries the constraint on `.cause` under a `Failed query: <sql>`
message, so without the translation an operator sees the statement and never the
reason. `iamIsForeignKeyViolation` walks the cause chain and matches on the
constraint text (portable across all three drivers) plus Postgres's SQLSTATE
`23503`.

`opts.actor` is written to `created_by` **by spread**, so an insert against a
table that predates the column names no such column unless an actor is supplied.

An admin write over HTTP names an actor when `authorize` returns a string, or
when `getMutationActor` maps its answer to one; see `server.md` §7.6. Until
both were wired these columns were null for every request-driven write, and
`admin.import` left them null even when the caller named an actor.

### 7.3 `assignRoleMany` and the column list

One multi-row insert. One subtlety worth stating: a multi-row insert builds its
column list from the value objects, so if *any* row names an actor, **every** row
carries `createdBy` — `null` where it has none (`index.ts:870`). Otherwise no row
carries the column at all.

### 7.4 `revokeRoleMany`

With `ops.or`, one `DELETE` whose `WHERE` is an OR of the per-triple conditions.
Without it, one `DELETE` per row — same rows removed, more statements. A row with
no `scope` revokes the role in every scope; a scoped row revokes only its own,
and `''` is a scope like any other, distinct from the unscoped row's `NULL` (and
refused by the scope guard anyway).

### 7.5 `updateAssignmentScope`

Moves a grant to a different scope with one `UPDATE`, preserving the row's `id`
and `created_at` instead of delete + create. Returning `false` is the signal the
engine uses to fall back to revoke + assign.

Drizzle (`index.ts:954`):

1. `if (!this._isNull) return false` — the unscoped case needs `IS NULL`.
2. Select the source row. Absent → `false`.
3. Select the target row. Present → delete the *source* and return `true`; the
   target scope is already granted, so collapsing onto it is the answer.
4. Otherwise `UPDATE ... SET scope = ?`, plus `updated_by` when an actor is named.

Prisma (`prisma/index.ts:521`) does the same with `findMany`/`deleteMany`/
`updateMany`, and its conflict-drop carries a hard-won correction. It used to
guard the source row with `NOT: { scope: fromScope }`, and on a nullable column
that is three-valued logic: moving `org-1` to global asked for
`scope IS NULL AND NOT (scope = 'org-1')`, whose second half is `NULL` for
exactly the rows the first half selected. The global row was never deleted, the
update left two of them, and which reading Prisma emitted for `NOT` had varied
across client versions. The clause is gone; the two scopes are compared in
JavaScript, where `null` compares the way it reads. The e2e suite runs both
readings of `NOT` so it stays that way.

### 7.6 Provenance

`created_by` answers "who first put this here" and must not move on a later
edit; `updated_by` answers "who touched it last" and must. `provenance(actor)`
(`index.ts:180`, `prisma/index.ts:164`) returns two disjoint records and the
upsert spreads one into `create`/`insert` and the other into `update`/`set`.
Getting this backwards silently rewrites who authored a policy every time
somebody edits it. Both are spread rather than written as `null`, so a table
predating the columns is untouched unless the caller actually names an actor.

`actor` is the one `IAssignOptions` field an adapter may drop without throwing.
Dropping `expiresAt` changes what the store will *answer*; dropping `actor`
changes nothing about a future authorization decision, because the engine emits
it on the `role.assigned` / `role.revoked` mutation event whether or not a column
exists (`src/shared/assign-options.ts`).

---

## 8. Prisma

### 8.1 What you declare

Copy the four models from `src/adapters/prisma/schema.prisma` into your own
schema. The adapter looks for the delegates `accessPolicy`, `accessRole`,
`accessAssignment` and `accessSubjectAttr` — model names, not table names; the
`@@map`s point them at the same `iam_*` tables the drizzle schemas use.

```prisma
model AccessAssignment {
  id        String     @id @default(cuid())
  subjectId String     @map("subject_id")
  roleId    String     @map("role_id")
  scope     String?
  role      AccessRole @relation(fields: [roleId], references: [id], onDelete: Cascade)
  createdBy String?    @map("created_by")
  updatedBy String?    @map("updated_by")
  createdAt DateTime   @default(now()) @map("created_at")
  updatedAt DateTime   @updatedAt @map("updated_at")

  @@unique([subjectId, roleId, scope])
  @@index([subjectId])
  @@index([roleId])
  @@index([subjectId, scope])
  @@map("iam_assignments")
}
```

The client is typed **structurally** against `IamPrisma.ILike`
(`prisma/index.ts:56`), not imported from `@prisma/client`. That keeps the
generated client — which every project generates differently — out of this
package's dependency graph, and it is also why a transaction handle is accepted
wherever the base client is.

### 8.2 The migration you must write by hand

`scope` is nullable, SQL unique indexes do not collapse NULLs, and Prisma can
express neither `NULLS NOT DISTINCT` nor a `coalesce` index. So
`@@unique([subjectId, roleId, scope])` does **not** prevent duplicate *unscoped*
grants, and you have to replace the index Prisma generates:

```sql
-- Postgres 15+
DROP INDEX "iam_assignments_subject_id_role_id_scope_key";
CREATE UNIQUE INDEX "iam_assignments_subject_id_role_id_scope_key"
  ON "iam_assignments" ("subject_id", "role_id", "scope") NULLS NOT DISTINCT;

-- MySQL / SQLite
CREATE UNIQUE INDEX "iam_assignments_subject_id_role_id_scope_key"
  ON "iam_assignments" ("subject_id", "role_id", (coalesce("scope", '')));
```

This is not hygiene. `assignRole` is a read-then-write — the composite key
includes a nullable column, so `upsert` cannot address the row — and a read
cannot make a write atomic. The index is what actually decides the outcome. The
e2e suite measures it: twenty concurrent identical unscoped grants left **three**
rows under the plain index and leave exactly one under `NULLS NOT DISTINCT`.

The adapter keeps the read as its fast path and treats the `P2002` a racing
writer causes as success (`isUniqueConstraintViolation`, `prisma/index.ts:137`) —
the row the caller asked for exists, which is the whole of what `assignRole`
promises. Twenty concurrent identical *scoped* grants used to produce nine
rejections. Do not replace the read-then-write with a bare `create`: without the
read, every repeat grant costs a round trip and a caught error.

### 8.3 An unreadable role row on Prisma

`src/adapters/prisma/__tests__/prisma-unreadable-role.test.ts` pins the current
behaviour, which is a recent correction. The row is **skipped, and named**:

- `listRoles` drops it, returns the readable rows, and warns once per bad row.
- `getRole` returns `null` and warns.
- The warning is
  `[@gentleduck/iam:prisma] unreadable role row "broken": <issues from validateRole>` —
  the actual validation issues, not just "it was bad".
- A fully readable catalog produces no warning at all.
- It still *skips* rather than throws. The fix changed the reporting, not the
  control flow; a policy is refused, a role is not (§6.1).

Before this, `listRoles` dropped the row with a bare `if (role !== null)` and
`getRole` returned `null`, with nothing written anywhere — so the same corrupt
row named itself on file, redis, http and drizzle and vanished on Prisma, while
Prisma's own *policy* path both threw and warned. Within one adapter the two
halves of "this row is unreadable" disagreed.

What an operator saw without the warning, quoted from `_readRole`
(`prisma/index.ts:345`): the role's permissions stop applying, every role
inheriting it silently loses that branch, and — because `resolveEffectiveRoles`
keeps a directly assigned id whether or not the catalog defines it — subjects
still *hold* the role id while it grants nothing. A support ticket with no log
line behind it.

Reporting is `console.warn` and not `onPolicyError` for a structural reason:
this adapter takes no options object, so there is nowhere to wire a handler
without changing its constructor.

### 8.4 How Prisma differs from Drizzle

| | Drizzle | Prisma |
| --- | --- | --- |
| `getSubjectGrantBoundary` | yes | **no** |
| `assignRoleMany` / `revokeRoleMany` | yes | **no** (engine loops) |
| `updateAssignmentScope` | yes (needs `ops.isNull`) | yes |
| `withClient` | yes | yes |
| Temporal grants (`startsAt`/`expiresAt`) | stored and enforced | **refused at the write** |
| Per-grant `attributes` | stored, surfaced on `IScopedRole` | **refused at the write** |
| Corrupt-row reporting | `onPolicyError`, falling back to `console.warn` | `console.warn` only |
| Deletes | `DELETE ... WHERE id = ?` | `deleteMany`, never `delete` |
| Unknown role on assign | FK, translated from the driver error | FK, translated from `P2003` |
| JSON encoding | `json: 'native' \| 'string'` | Prisma's own `Json` handling; never a string |

The support matrix is declared once in
`src/adapters/__compliance__/optional-support.ts` and checked against the real
prototypes by `optional-method-matrix.test.ts`, so a method that disappears
turns a row red instead of turning asserting tests into skipped ones.

Three of these deserve a sentence each.

**Temporal grants.** `schema.prisma` has no `starts_at`/`expires_at`/
`attributes` columns, deliberately, and `assignRole` calls
`iamAssertNoAssignOptions` so those options **throw** rather than being dropped
silently. A break-glass grant issued with `expiresAt` against an adapter that
discards it is permanent while the batch API still reports
`ok: true, applied: 1`. If you need time-boxed or attributed grants, use the
drizzle adapter.

**`deleteMany`.** Prisma's `delete` raises `P2025` when nothing matches, so
deleting a row that is already gone threw on Prisma and no-opped on the other
five adapters. `deletePolicy` and `deleteRole` use `deleteMany` so an idempotent
admin retry does not depend on the backend.

**`P2003` translation.** The relation was always declared, so the database
always refused a grant naming an unstored role — but Prisma leaked
``Foreign key constraint failed on the field: `roleId` `` straight from the
driver where the other five raise the shared refusal. A caller cannot branch on
that sentence, and it names a column of a schema the operator did not
necessarily write. Prisma's error *code* is matched rather than its message text,
because the code does not move with the server's locale.

**Prisma hands back already-parsed JSON.** A `rules` column that arrives as a
*string* — the shape a TEXT column migrated in from another adapter produces —
is refused, not parsed. `'[]'` read loosely looks like a policy with no rules,
which under `deny-overrides` denies nothing.

---

## 9. Transactions

Both SQL adapters implement `withClient(client)`, which is the whole of the
adapter's side of the transaction contract: re-make this adapter against the
opaque driver handle, keeping every other config field. That handle is never
inspected by the engine — it goes straight to the adapter, which is the only
layer that knows what a drizzle db or a Prisma `tx` actually is.

```ts
let pending
await db.transaction(async (tx) => {
  const perms = engine.withTransaction(tx)
  await perms.admin.assignRole(userId, 'admin', orgId)
  await tx.insert(members).values({ userId, orgId })
  pending = perms.pending
})
await pending.flush()   // invalidate and broadcast only after the commit
```

The README's "Transactions" section is accurate and this document agrees with it
in full. Three points it makes that this layer is responsible for:

1. **`withTransaction` throws without `withClient`.** Memory, file, redis and
   http do not implement it — they have no transaction to join — and the engine
   refuses rather than silently leaving the writes outside yours
   (`engine.ts:1322`). Drizzle and Prisma are the two that do.
2. **Reads on the bound view run against transaction-local caches**, so a
   read-after-write inside the transaction sees the transaction's own uncommitted
   grants; the shared engine keeps answering from its warm caches, which the
   transaction never pollutes.
3. **Cache invalidations do not fire inside a transaction**, including the
   `config.invalidator` fleet broadcast. They buffer in `pending`, de-duplicated,
   and fire on `flush()`. A rolled-back grant therefore never evicts another
   node's cache for a write that did not happen. `pending.discard()` drops the
   buffer explicitly.

What the adapter layer adds:

- `withClient` returns a **new** adapter; the original keeps writing to its own
  client. Both suites assert the negative half — that the write lands on the
  rebound client and *nowhere near* the original — because a `return this` mutant
  satisfies "a function exists" and still commits inside a rolled-back
  transaction (`with-client.test.ts`, `prisma-with-client.test.ts`).
- The rest of the drizzle config crosses the rebind: `json: 'string'` in
  particular, or a rebound adapter would write a different encoding into the same
  columns mid-transaction.
- Reads go to the rebound client too, not only writes.
- `withClient` re-runs the constructor, which re-runs `warnMissingOps` — hence
  the module-level warning set (§4).

A drizzle transaction handle exposes the same `select`/`insert`/`update`/
`delete` builders as the db it came from; a Prisma interactive-transaction `tx`
exposes the same delegates as the base client minus `$transaction` itself. In
both cases every read and write the adapter makes joins the caller's transaction
unchanged.

---

## 10. Gotchas

- **`json: 'native'` against the SQLite schema.** Nothing checks the
  combination. Set `json: 'string'`.
- **Forgetting `dialect: 'mysql'`.** Every method that inserts fails at runtime
  on a builder method MySQL does not have. The deletes and
  `updateAssignmentScope` keep working, so the symptom is lopsided rather than
  total.
- **Reading `assignRoleMany`'s `null` as "nothing written".** It means "the
  driver cannot say which rows were new" — MySQL, always.
- **Expecting `getSubjectRoles` to return everything.** It returns *unscoped*
  grants only, on both adapters. Scoped grants come from
  `getSubjectScopedRoles`. A caller that treats the first as "every role"
  under-reports.
- **Expecting `getSubjectAttributes` to answer `{}` for a corrupt row.** It
  throws. Corruption is not emptiness, and the ABAC bag is where a deny rule
  reads its inputs.
- **One corrupt policy row denies everything.** By design. Repair or delete the
  row; `onPolicyError` names it before anything throws.
- **Prisma without the `NULLS NOT DISTINCT` migration** accumulates duplicate
  unscoped grants under concurrency. The reads still answer one role and the
  revoke still clears all of them, so the damage is table growth rather than a
  wrong decision — but the fix is a migration, not a code change.
- **Passing `startsAt`/`expiresAt`/`attributes` to Prisma's `assignRole`**
  throws. That is the fix, not the bug: silently dropping an expiry made
  break-glass grants permanent.
- **`scope: ''` and `scope: '*'`** are refused on a grant. Omit the scope for a
  global assignment.
- **A MySQL `saveRole` race** on the same new id fails on the primary key, where
  pg/sqlite's target-scoped upsert would have merged. Loud, but dialect-specific.

## See also

- [`adapters-runtime.md`](./adapters-runtime.md) — the memory, file, http and
  redis adapters, and the shared compliance suite every adapter here is run
  against.
- [`core-schema.md`](./core-schema.md) — `validatePolicy` / `validateRole` /
  `parsePolicyRow` / `parseRoleRow`, the validators the read and write paths call.
- [`core-rbac.md`](./core-rbac.md) — scoped-role enrichment and how a stored
  `scope` is matched at request time.
- [`../../README.md`](../../README.md) — install, quick start, and the
  Transactions section this document agrees with.
