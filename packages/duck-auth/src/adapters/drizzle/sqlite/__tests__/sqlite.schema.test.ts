/** The sqlite schema's own declarations, against the DDL a deployment is handed. */

import Database from 'better-sqlite3'
import { drizzle } from 'drizzle-orm/better-sqlite3'
import { getTableConfig } from 'drizzle-orm/sqlite-core'
import { beforeAll, describe, expect, it } from 'vitest'
import { SQLITE_DDL as DDL } from '~/test/sqlite-schema'
import {
  authCredentials,
  authIdentities,
  authIdentityProviders,
  authSessions,
  authSqliteSchema,
} from '../sqlite.schema'

const TABLES = [authIdentities, authIdentityProviders, authCredentials, authSessions]

function declared(table: (typeof TABLES)[number]) {
  const config = getTableConfig(table)
  return {
    checks: config.checks.map((c) => c.name),
    foreignKeys: config.foreignKeys.map((f) => {
      const ref = f.reference()
      return { column: ref.columns[0]?.name ?? '', table: getTableConfig(ref.foreignTable).name }
    }),
    indexes: config.indexes.map((i) => i.config.name),
    name: config.name,
    uniques: config.uniqueConstraints.map((u) => u.name),
  }
}

describe('every declaration reaches the generated DDL', () => {
  it.each(TABLES.map((t) => [getTableConfig(t).name, t] as const))('%s', (_name, table) => {
    const table_ = declared(table)
    for (const check of table_.checks) expect(DDL).toContain(`CONSTRAINT "${check}"`)
    for (const index of [...table_.indexes, ...table_.uniques]) expect(DDL).toContain(`INDEX \`${index}\``)
    for (const fk of table_.foreignKeys) {
      expect(DDL).toContain(`FOREIGN KEY (\`${fk.column}\`) REFERENCES \`${fk.table}\``)
    }
  })

  it('carries nothing the schema no longer declares', () => {
    // The other direction, which is the one a stale file fails: a check deleted from the schema and
    // never regenerated stays in the DDL, and every suite keeps testing against it.
    const checks = new Set(TABLES.flatMap((t) => declared(t).checks))
    const indexes = new Set(TABLES.flatMap((t) => [...declared(t).indexes, ...declared(t).uniques]))

    const inDdl = [...DDL.matchAll(/CONSTRAINT "([^"]+)"/g)].map((m) => m[1] ?? '')
    const indexedInDdl = [...DDL.matchAll(/CREATE (?:UNIQUE )?INDEX `([^`]+)`/g)].map((m) => m[1] ?? '')

    expect(inDdl.filter((n) => !checks.has(n))).toEqual([])
    expect(indexedInDdl.filter((n) => !indexes.has(n))).toEqual([])
    expect(inDdl.length).toBe(checks.size)
    expect(indexedInDdl.length).toBe(indexes.size)
  })
})

describe('the relational query API the schema registers', () => {
  const IDENTITY = 'rel-identity'
  const SID = 'a'.repeat(64)
  const sqlite = new Database(':memory:')
  const db = drizzle(sqlite, { schema: authSqliteSchema })

  beforeAll(() => {
    const now = Date.now()
    sqlite.exec(DDL)
    sqlite.exec(
      `INSERT INTO auth_identities (id, profile, version, email_verified, created_at, updated_at)
       VALUES ('${IDENTITY}', '{"email":"rel@x.local","username":"rel"}', 1, 1, ${now}, ${now})`,
    )
    sqlite.exec(
      `INSERT INTO auth_identity_providers (id, identity_id, provider_id, provider_sub, added_at)
       VALUES ('p1', '${IDENTITY}', 'oauth:google', 'sub-1', ${now})`,
    )
    sqlite.exec(
      `INSERT INTO auth_credentials (id, identity_id, kind, secret, version, created_at, updated_at)
       VALUES ('c1', '${IDENTITY}', 'password', 'hashed', 1, ${now}, ${now})`,
    )
    sqlite.exec(
      `INSERT INTO auth_sessions (id, identity_id, kind, aal, rotated_at, expires_at, absolute_expires_at, fresh, created_at, updated_at)
       VALUES ('${SID}', '${IDENTITY}', 'user', 1, ${now}, ${now + 1000}, ${now + 2000}, 1, ${now}, ${now})`,
    )
  })

  it('reads an identity with its providers, credentials and sessions in one query', async () => {
    const row = await db.query.authIdentities.findFirst({
      with: { credentials: true, providers: true, sessions: true },
    })
    expect(row?.providers).toHaveLength(1)
    expect(row?.credentials).toHaveLength(1)
    expect(row?.sessions).toHaveLength(1)
  })
})
