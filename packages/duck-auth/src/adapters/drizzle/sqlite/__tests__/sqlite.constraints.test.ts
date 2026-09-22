/** The constraints added by the schema audit, against a live database rather than the DDL text. */

import { beforeAll, describe, expect, it } from 'vitest'
import { SQLITE_DDL as DDL } from '~/test/sqlite-schema'

const IS_BUN = typeof (globalThis as { Bun?: unknown }).Bun !== 'undefined'

type Db = { exec(sql: string): void; close?(): void }

let open: () => Db

beforeAll(async () => {
  if (IS_BUN) {
    const { Database } = (await import('bun:sqlite' as string)) as { Database: new (path: string) => Db }
    open = () => {
      const db = new Database(':memory:')
      db.exec('pragma foreign_keys = on')
      db.exec(DDL)
      return db
    }
    return
  }
  const { default: Database } = (await import('better-sqlite3' as string)) as {
    default: new (path: string) => Db
  }
  open = () => {
    const db = new Database(':memory:')
    db.exec('pragma foreign_keys = on')
    db.exec(DDL)
    return db
  }
})

const quote = (v: string | null) => (v === null ? 'NULL' : `'${v}'`)

function identity(db: Db, id: string, email: string, username: string): void {
  db.exec(
    `INSERT INTO auth_identities (id, profile, version, email_verified, created_at, updated_at)
     VALUES ('${id}', '${JSON.stringify({ email, username })}', 1, 1, 0, 0)`,
  )
}

function credential(db: Db, id: string, identityId: string, kind: string, secret: string, tenantId: string | null) {
  db.exec(
    `INSERT INTO auth_credentials (id, identity_id, tenant_id, kind, secret, version, created_at, updated_at)
     VALUES ('${id}', '${identityId}', ${quote(tenantId)}, '${kind}', '${secret}', 1, 0, 0)`,
  )
}

describe('uq_auth_credentials_password', () => {
  let db: Db

  beforeAll(() => {
    db = open()
    identity(db, 'i1', 'a@x.com', 'alice')
  })

  it('refuses a second password for the same identity', () => {
    credential(db, 'c1', 'i1', 'password', 'h1', null)
    expect(() => credential(db, 'c2', 'i1', 'password', 'h2', null)).toThrow()
  })

  it('lets each tenant hold its own, since setPassword deletes within a tenant', () => {
    expect(() => credential(db, 'c3', 'i1', 'password', 'h3', 't1')).not.toThrow()
    expect(() => credential(db, 'c4', 'i1', 'password', 'h4', 't1')).toThrow()
  })

  it('constrains no other kind', () => {
    credential(db, 'c5', 'i1', 'totp', 's1', null)
    expect(() => credential(db, 'c6', 'i1', 'totp', 's2', null)).not.toThrow()
  })

  // NOTE: `(kind, secret)` is deliberately NOT unique - `findByHashedSecret` is specified to answer the
  // freshest live row and fall back to a revoked one, which needs both to exist at once.
  it('leaves a revoked and a live row under one secret hash', () => {
    identity(db, 'i2', 'b@x.com', 'bob')
    credential(db, 'c7', 'i2', 'magic-link', 'same', null)
    expect(() => credential(db, 'c8', 'i2', 'magic-link', 'same', null)).not.toThrow()
  })
})

describe('profile length caps', () => {
  it('refuses an address past the width mysql types the norm column', () => {
    const db = open()
    expect(() => identity(db, 'i3', `${'a'.repeat(320)}@x.com`, 'carol')).toThrow()
    expect(() => identity(db, 'i4', 'ok@x.com', 'd'.repeat(300))).toThrow()
    expect(() => identity(db, 'i5', 'ok@x.com', 'dave')).not.toThrow()
  })
})
