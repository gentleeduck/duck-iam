/** The sqlite adapter's async-driver path. */

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { BaseSQLiteDatabase } from 'drizzle-orm/sqlite-core'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { SQLITE_DDL as DDL } from '~/test/sqlite-schema'
import { DrizzleSqliteAdapter } from '../sqlite'

const IS_BUN = typeof (globalThis as { Bun?: unknown }).Bun !== 'undefined'

type Conn = {
  exec(sql: string): void
  prepare(sql: string): { get(...args: unknown[]): unknown }
}

/** What the adapter itself accepts: any drizzle sqlite handle, either result kind. */
type AnyDb = BaseSQLiteDatabase<'sync' | 'async', unknown, Record<string, unknown>>

describe('DrizzleSqlite over an async driver', () => {
  let dir: string
  let connA: Conn
  let connB: Conn
  let adapter: DrizzleSqliteAdapter<Record<string, unknown>, { email: string; username: string }>

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'duck-auth-async-sqlite-'))
    const file = join(dir, 'auth.db')

    // Each branch wraps its own driver, because the two `drizzle` overload sets do not form a callable union.
    const open: (path: string) => Promise<{ conn: Conn; db: AnyDb }> = IS_BUN
      ? async (path) => {
          const { Database } = (await import('bun:sqlite' as string)) as { Database: new (p: string) => Conn }
          const { drizzle } = await import('drizzle-orm/bun-sqlite')
          const conn = new Database(path)
          // biome-ignore lint/suspicious/noExplicitAny: bun:sqlite Database is structurally the drizzle client.
          return { conn, db: drizzle(conn as any) }
        }
      : async (path) => {
          const { default: Database } = await import('better-sqlite3')
          const { drizzle } = await import('drizzle-orm/better-sqlite3')
          const conn = new Database(path) as unknown as Conn
          // biome-ignore lint/suspicious/noExplicitAny: better-sqlite3 Database is structurally the drizzle client.
          return { conn, db: drizzle(conn as any) }
        }

    // WAL is what lets B hold a write open while A still reads; without it A would block instead.
    const a = await open(file)
    connA = a.conn
    connA.exec('pragma journal_mode = wal')
    connA.exec(DDL)
    connA.exec('pragma foreign_keys = on')

    const b = await open(file)
    connB = b.conn
    connB.exec('pragma foreign_keys = on')

    const dbA = a.db
    const dbB = b.db

    // The adapter's handle, answering `async` so `_atomic` takes the driver's own transaction, and handing
    // that transaction a handle on the other connection — the split a sync driver does not have.
    const handle = new Proxy(dbA, {
      get(target, prop, receiver) {
        if (prop === 'resultKind') return 'async'
        if (prop === 'transaction') {
          return async (run: (tx: typeof dbB) => Promise<unknown>) => {
            connB.exec('begin immediate')
            try {
              const out = await run(dbB)
              connB.exec('commit')

              return out
            } catch (err) {
              connB.exec('rollback')
              throw err
            }
          }
        }

        return Reflect.get(target, prop, receiver)
      },
    })

    adapter = new DrizzleSqliteAdapter(handle)
  })

  afterAll(() => rmSync(dir, { recursive: true, force: true }))

  it('the fixture reproduces the hazard: the adapter handle is blind to an open transaction', () => {
    connB.exec('begin immediate')
    connB.exec(
      `INSERT INTO auth_identities (id, profile, version, email_verified, created_at, updated_at)
       VALUES ('blind-probe', '{"email":"p@x.local","username":"p"}', 1, 0, 0, 0)`,
    )
    const seenByB = connB.prepare(`select count(*) as n from auth_identities where id = 'blind-probe'`).get()
    const seenByA = connA.prepare(`select count(*) as n from auth_identities where id = 'blind-probe'`).get()
    connB.exec('rollback')

    expect((seenByB as { n: number }).n).toBe(1)
    // If this ever reads 1 the two handles have stopped being separate connections, and every other
    // assertion in this file goes quietly toothless.
    expect((seenByA as { n: number }).n).toBe(0)
  })

  it('link answers with the login it just wrote, which only the transaction can see', async () => {
    const created = await adapter.identities.create({
      emailVerified: false,
      profile: { email: 'async@x.local', username: 'async' },
      providers: [],
    })

    const linked = await adapter.identities.link(created.id, { providerId: 'oauth:test', providerSub: 'sub-1' })

    expect(linked.providers.map((p) => p.providerSub)).toEqual(['sub-1'])
  })

  it('unlink answers with the logins left standing, read inside the same transaction', async () => {
    const created = await adapter.identities.create({
      emailVerified: false,
      profile: { email: 'async2@x.local', username: 'async2' },
      providers: [
        { providerId: 'oauth:a', providerSub: 'a-1' },
        { providerId: 'oauth:b', providerSub: 'b-1' },
      ],
    })

    const left = await adapter.identities.unlink(created.id, 'oauth:a')

    expect(left.providers.map((p) => p.providerId)).toEqual(['oauth:b'])
  })
})
