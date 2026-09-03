import { getTableConfig } from 'drizzle-orm/mysql-core'
import { describe, expect, it } from 'vitest'
import { authCredentials, authEvents, authIdentities, authSessions } from '~/adapters/drizzle/mysql/mysql.schema'
import { renderMigration } from '../index'

/**
 * `duck-auth migrate` emits DDL by hand while the drizzle adapters declare the
 * same tables in TypeScript, so the two drift silently. That is how
 * `email_verified`, `created_by`, `updated_by` and both `updated_at` columns
 * went missing, how `auth_events` went unemitted entirely, and how the CLI came
 * to emit an `auth_identities.tenant_id` that no query in any dialect reads.
 *
 * Both directions are checked, because both are defects and they fail
 * differently. A column the schema declares and the CLI omits breaks writes
 * outright: the adapter names a column the database does not have. A column the
 * CLI emits and no schema declares is the quieter one - it is created, nothing
 * ever writes it, and it reads as data forever after. That is the same defect
 * this release removed from `auth_sessions`, so the test that would have caught
 * it belongs here.
 *
 * MySQL is the reference because its schema is the widest.
 */
/**
 * Carriers for the MySQL unique indexes, not columns of the row contract. They
 * exist because MySQL cannot index a JSON path directly; pg and sqlite express
 * the same two indexes over the profile inline and declare nothing extra. The
 * CLI targets the generic bridge, which stores the profile as text, so it has
 * neither these nor the indexes - uniqueness is the bridge author's to enforce.
 */
const MYSQL_INDEX_CARRIERS = new Set(['email_norm', 'username_norm'])

const TABLES = [
  {
    columns: () => getTableConfig(authIdentities).columns.filter((c) => !MYSQL_INDEX_CARRIERS.has(c.name)),
    suffix: 'identities',
  },
  { columns: () => getTableConfig(authCredentials).columns, suffix: 'credentials' },
  { columns: () => getTableConfig(authSessions).columns, suffix: 'sessions' },
  { columns: () => getTableConfig(authEvents).columns, suffix: 'events' },
] as const

/** Column names in one emitted `CREATE TABLE` body. */
function emittedColumns(ddl: string, suffix: string): Set<string> {
  const start = ddl.indexOf(`CREATE TABLE IF NOT EXISTS auth_${suffix} (`)
  if (start === -1) throw new Error(`migrate emits no auth_${suffix} table`)
  const body = ddl.slice(start)
  return new Set(
    body
      .slice(body.indexOf('(') + 1, body.indexOf(');'))
      .split(',')
      .map((line) => line.trim().split(/\s+/)[0] ?? '')
      .filter(Boolean),
  )
}

describe('migrate DDL matches the declared schema', () => {
  for (const dialect of ['pg', 'mysql', 'sqlite'] as const) {
    for (const { columns, suffix } of TABLES) {
      it(`${dialect}: auth_${suffix} emits every column the schema declares`, () => {
        const emitted = emittedColumns(renderMigration(dialect, 'auth_'), suffix)
        const missing = columns()
          .map((c) => c.name)
          .filter((name) => !emitted.has(name))
        expect(missing).toEqual([])
      })

      it(`${dialect}: auth_${suffix} emits no column the schema does not declare`, () => {
        const emitted = emittedColumns(renderMigration(dialect, 'auth_'), suffix)
        const declared = new Set(columns().map((c) => c.name))
        expect([...emitted].filter((name) => !declared.has(name))).toEqual([])
      })
    }
  }

  /**
   * The column exists to answer "everything operator X did". `auth_events` is
   * append-only and unbounded, so an unindexed lookup degrades with the log.
   */
  it('indexes auth_events.actor_id, which is the only reason the column is useful', () => {
    for (const dialect of ['pg', 'mysql', 'sqlite'] as const) {
      expect(renderMigration(dialect, 'auth_')).toContain('auth_events(actor_id, created_at)')
    }
  })
})
