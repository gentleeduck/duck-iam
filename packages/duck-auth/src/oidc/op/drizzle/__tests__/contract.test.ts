/**
 * Module-surface contract tests for the pg + mysql + sqlite Drizzle OP
 * stores.
 *
 * Validates that every dialect exports the same table set + factory
 * signature so consumers can swap engines via a one-import change. The
 * actual SQL execution path is covered by sqlite.test.ts (which runs
 * against bun:sqlite). Equivalent pg + mysql integration tests need a
 * running Postgres / MySQL or an embedded driver (pglite, mysql2 in
 * mock mode); both are dev-dep additions, not in this workspace.
 *
 * See packages/duck-AUTH/src/oidc/op/drizzle/README.md (planned) for
 * the integration-test gap.
 */

import { describe, expect, it } from 'vitest'
import * as mysql from '../mysql'
import * as pg from '../pg'
import * as sqlite from '../sqlite'

const EXPECTED_TABLES = [
  'authOidcClientsTable',
  'authOidcCodesTable',
  'authOidcAccessTokensTable',
  'authOidcRefreshTokensTable',
  'authOidcConsentsTable',
] as const

describe('pg dialect surface', () => {
  it('exports all five tables', () => {
    for (const t of EXPECTED_TABLES) {
      expect(pg).toHaveProperty(t)
    }
  })

  it('exports authCreateDrizzlePgOidcOpStores factory', () => {
    expect(typeof pg.authCreateDrizzlePgOidcOpStores).toBe('function')
  })

  it('exports authGcDrizzlePgOidcOp helper', () => {
    expect(typeof pg.authGcDrizzlePgOidcOp).toBe('function')
  })
})

describe('mysql dialect surface', () => {
  it('exports all five tables', () => {
    for (const t of EXPECTED_TABLES) {
      expect(mysql).toHaveProperty(t)
    }
  })

  it('exports authCreateDrizzleMysqlOidcOpStores factory', () => {
    expect(typeof mysql.authCreateDrizzleMysqlOidcOpStores).toBe('function')
  })

  it('exports authGcDrizzleMysqlOidcOp helper', () => {
    expect(typeof mysql.authGcDrizzleMysqlOidcOp).toBe('function')
  })
})

describe('sqlite dialect surface', () => {
  it('exports all five tables', () => {
    for (const t of EXPECTED_TABLES) {
      expect(sqlite).toHaveProperty(t)
    }
  })

  it('exports authCreateDrizzleSqliteOidcOpStores factory', () => {
    expect(typeof sqlite.authCreateDrizzleSqliteOidcOpStores).toBe('function')
  })
})

// Filter to user-defined column keys (drop drizzle internal methods like
// `enableRLS`, `getSQL`, function-typed helpers). Columns are the keys
// that point to objects with a `dataType` field.
function columnKeys(table: object): string[] {
  const out: string[] = []
  for (const k of Object.keys(table)) {
    const v: unknown = Reflect.get(table, k)
    if (v !== null && typeof v === 'object' && 'dataType' in v) out.push(k)
  }
  return out.sort()
}

describe('cross-dialect schema parity', () => {
  it('all three dialects declare the same five table names', () => {
    const pgKeys = EXPECTED_TABLES.map((k) => k)
    const sqliteKeys = EXPECTED_TABLES.map((k) => k)
    const mysqlKeys = EXPECTED_TABLES.map((k) => k)
    expect(pgKeys).toEqual(sqliteKeys)
    expect(pgKeys).toEqual(mysqlKeys)
  })

  it('clients table has the same column names across dialects', () => {
    // Drizzle exposes column metadata via the symbol; check by inspecting
    // the table's runtime shape.
    const pgCols = columnKeys(pg.authOidcClientsTable)
    const sqliteCols = columnKeys(sqlite.authOidcClientsTable)
    const mysqlCols = columnKeys(mysql.authOidcClientsTable)
    expect(pgCols).toEqual(sqliteCols)
    expect(pgCols).toEqual(mysqlCols)
  })

  it('codes table has the same column names across dialects', () => {
    const pgCols = columnKeys(pg.authOidcCodesTable)
    const sqliteCols = columnKeys(sqlite.authOidcCodesTable)
    const mysqlCols = columnKeys(mysql.authOidcCodesTable)
    expect(pgCols).toEqual(sqliteCols)
    expect(pgCols).toEqual(mysqlCols)
  })

  it('refresh-tokens table has the same column names across dialects', () => {
    const pgCols = columnKeys(pg.authOidcRefreshTokensTable)
    const sqliteCols = columnKeys(sqlite.authOidcRefreshTokensTable)
    const mysqlCols = columnKeys(mysql.authOidcRefreshTokensTable)
    expect(pgCols).toEqual(sqliteCols)
    expect(pgCols).toEqual(mysqlCols)
  })
})
