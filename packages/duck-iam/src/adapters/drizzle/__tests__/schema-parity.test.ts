// Diffs the three hand-written drizzle schemas, which describe one logical schema.
// Legitimate dialect differences are named in `DIALECT_ONLY`; anything else is drift.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { type MySqlTable, getTableConfig as mysqlConfig } from 'drizzle-orm/mysql-core'
import { type PgTable, getTableConfig as pgConfig } from 'drizzle-orm/pg-core'
import { type SQLiteTable, getTableConfig as sqliteConfig } from 'drizzle-orm/sqlite-core'
import { describe, expect, it } from 'vitest'
import * as mysql from '../mysql/mysql.schema'
import * as pg from '../pg/pg.schema'
import * as sqlite from '../sqlite/sqlite.schema'

/** What a table declares, flattened to the parts every dialect can express. */
interface IShape {
  readonly columns: readonly string[]
  /** Index and unique-constraint names together, since dialects file a unique index under different lists. */
  readonly indexes: readonly string[]
  readonly checks: readonly string[]
  readonly foreignKeys: readonly string[]
  /** Columns that are NOT NULL with no default - a caller must supply them on every insert. */
  readonly required: readonly string[]
}

/** The fields the three dialects' `getTableConfig` results agree on. */
interface ITableConfigLike {
  readonly columns: readonly { readonly name: string; readonly notNull: boolean; readonly hasDefault: boolean }[]
  readonly indexes: readonly { readonly config: { readonly name?: string | undefined } }[]
  readonly uniqueConstraints: readonly { readonly name?: string | undefined }[]
  readonly checks: readonly { readonly name: string }[]
  readonly foreignKeys: readonly { getName(): string }[]
}

function shapeOf(cfg: ITableConfigLike): IShape {
  // An unnamed index or unique constraint is legal in drizzle and is a schema
  // this file cannot compare, so it is surfaced rather than quietly skipped.
  const named = (name: string | undefined, kind: string): string => {
    if (name === undefined) throw new Error(`unnamed ${kind}: this schema cannot be compared`)
    return name
  }
  const indexNames = cfg.indexes.map((i) => named(i.config.name, 'index'))
  return {
    checks: cfg.checks.map((c) => c.name).sort(),
    columns: cfg.columns.map((c) => c.name).sort(),
    foreignKeys: cfg.foreignKeys.map((f) => f.getName()).sort(),
    indexes: [...indexNames, ...cfg.uniqueConstraints.map((u) => named(u.name, 'unique constraint'))].sort(),
    required: cfg.columns
      .filter((c) => c.notNull && !c.hasDefault)
      .map((c) => c.name)
      .sort(),
  }
}

const shape = {
  mysql: (t: MySqlTable) => shapeOf(mysqlConfig(t)),
  pg: (t: PgTable) => shapeOf(pgConfig(t)),
  sqlite: (t: SQLiteTable) => shapeOf(sqliteConfig(t)),
}

/** Entries only one dialect has because the others cannot express them - never because a port is pending. */
const DIALECT_ONLY: Readonly<Record<string, string>> = {
  // GIN over a jsonb column. MySQL and SQLite have no equivalent that does not
  // require a generated column per query shape.
  idx_iam_policies_rules_gin: 'pg',
  idx_iam_roles_permissions_gin: 'pg',
  // Postgres has an enum type and MySQL has ENUM; SQLite has neither, so the
  // same closed set has to be a CHECK there.
  ch_iam_policies_algorithm_valid: 'sqlite',
}

const TABLES = [
  { mysql: mysql.iamPolicies, name: 'iam_policies', pg: pg.iamPolicies, sqlite: sqlite.iamPolicies },
  { mysql: mysql.iamRoles, name: 'iam_roles', pg: pg.iamRoles, sqlite: sqlite.iamRoles },
  { mysql: mysql.iamAssignments, name: 'iam_assignments', pg: pg.iamAssignments, sqlite: sqlite.iamAssignments },
  { mysql: mysql.iamSubjectAttrs, name: 'iam_subject_attrs', pg: pg.iamSubjectAttrs, sqlite: sqlite.iamSubjectAttrs },
] as const

/** Drops the names this dialect is documented as owning alone. */
function shared(names: readonly string[], dialect: string): string[] {
  return names.filter((n) => DIALECT_ONLY[n] !== dialect)
}

describe.each(TABLES)('$name declares the same shape on every dialect', (table) => {
  const p = shape.pg(table.pg)
  const m = shape.mysql(table.mysql)
  const s = shape.sqlite(table.sqlite)

  it('has the same columns', () => {
    expect(m.columns).toEqual(p.columns)
    expect(s.columns).toEqual(p.columns)
  })

  it('requires the same columns on insert', () => {
    // A column that is NOT NULL with a default on one dialect and NOT NULL
    // without one on another makes the same insert succeed here and fail there.
    expect(m.required).toEqual(p.required)
    expect(s.required).toEqual(p.required)
  })

  it('declares the same indexes and unique constraints', () => {
    expect(shared(m.indexes, 'mysql')).toEqual(shared(p.indexes, 'pg'))
    expect(shared(s.indexes, 'sqlite')).toEqual(shared(p.indexes, 'pg'))
  })

  it('declares the same CHECK constraints', () => {
    // A check missing on one dialect makes the same value storable there and rejected elsewhere.
    expect(shared(m.checks, 'mysql')).toEqual(shared(p.checks, 'pg'))
    expect(shared(s.checks, 'sqlite')).toEqual(shared(p.checks, 'pg'))
  })

  it('declares the same foreign keys', () => {
    expect(m.foreignKeys).toEqual(p.foreignKeys)
    expect(s.foreignKeys).toEqual(p.foreignKeys)
  })
})

describe('the dialect-only allow-list stays honest', () => {
  it('names only entries that actually exist on the dialect claimed', () => {
    const byDialect = new Map<string, Set<string>>([
      ['mysql', new Set<string>()],
      ['pg', new Set<string>()],
      ['sqlite', new Set<string>()],
    ])
    for (const table of TABLES) {
      for (const [dialect, s] of [
        ['pg', shape.pg(table.pg)],
        ['mysql', shape.mysql(table.mysql)],
        ['sqlite', shape.sqlite(table.sqlite)],
      ] as const) {
        const bucket = byDialect.get(dialect)
        if (bucket === undefined) continue
        for (const n of [...s.indexes, ...s.checks]) bucket.add(n)
      }
    }
    for (const [name, dialect] of Object.entries(DIALECT_ONLY)) {
      expect(byDialect.get(dialect)?.has(name), `${name} claimed for ${dialect}`).toBe(true)
    }
  })
})

// `src/test/pg-e2e-schema.sql` hand-mirrors `pg.schema.ts`, so drift lets e2e pass on a schema consumers never get.
// Compares what a regex reads reliably: column names and named constraints and indexes.
describe('the e2e SQL mirror matches the Postgres schema module', () => {
  const SQL = readFileSync(join(import.meta.dirname, '../../../test/pg-e2e-schema.sql'), 'utf8')

  /** Every `CREATE TABLE <name> ( ... );` body in the file, by table name. */
  function tableBody(name: string): string {
    const m = new RegExp(`CREATE TABLE IF NOT EXISTS ${name} \\(([\\s\\S]*?)\\n\\);`).exec(SQL)
    if (m?.[1] === undefined) throw new Error(`no CREATE TABLE for ${name}`)
    return m[1]
  }

  describe.each(TABLES)('$name', (table) => {
    const body = tableBody(table.name)
    const expected = shape.pg(table.pg)

    it('declares the same columns', () => {
      const columns = [...body.matchAll(/^ {2}([a-z_]+) +[a-z]/gm)].map((m) => m[1]).sort()
      expect(columns).toEqual(expected.columns)
    })

    it('declares the same named constraints', () => {
      const named = [...body.matchAll(/CONSTRAINT ([a-z_]+)/g)].map((m) => m[1]).sort()
      const fromModule = [...expected.checks, ...expected.foreignKeys, ...expected.indexes, `pk_${table.name}`]
        .filter((n) => !n.startsWith('idx_'))
        .sort()
      expect(named).toEqual(fromModule)
    })

    it('declares the same indexes', () => {
      const created = [...SQL.matchAll(/CREATE INDEX IF NOT EXISTS (\w+) ON (\w+)/g)]
        .filter((m) => m[2] === table.name)
        .map((m) => m[1])
        .sort()
      expect(created).toEqual([...expected.indexes].filter((n) => n.startsWith('idx_')).sort())
    })
  })
})
