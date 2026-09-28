/** The sqlite adapter's async-driver path. */

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Database from 'better-sqlite3'
import { drizzle } from 'drizzle-orm/better-sqlite3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { SQLITE_DDL as DDL } from '~/test/sqlite-schema'
import { DrizzleSqliteAdapter } from '../sqlite'

describe('DrizzleSqlite over an async driver', () => {
  let dir: string
  let connA: Database.Database
  let connB: Database.Database
  let adapter: DrizzleSqliteAdapter<Record<string, unknown>, { email: string; username: string }>

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'duck-auth-async-sqlite-'))
    const file = join(dir, 'auth.db')

    // WAL is what lets B hold a write open while A still reads; without it A would block instead.
    connA = new Database(file)
    connA.exec('pragma journal_mode = wal')
    connA.exec(DDL)
    connA.exec('pragma foreign_keys = on')

    connB = new Database(file)
    connB.exec('pragma foreign_keys = on')

    const dbA = drizzle(connA)
    const dbB = drizzle(connB)

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

  afterAll(() => {
    connA.close()
    connB.close()
    rmSync(dir, { recursive: true, force: true })
  })

  it('the fixture reproduces the hazard: the adapter handle is blind to an open transaction', () => {
    connB.exec('begin immediate')
    connB.exec(
      `INSERT INTO auth_identities (id, profile, version, email_verified, created_at, updated_at)
       VALUES ('blind-probe', '{"email":"p@x.local","username":"p"}', 1, 0, 0, 0)`,
    )
    const seenByB = connB.prepare(`select count(*) from auth_identities where id = 'blind-probe'`).pluck().get()
    const seenByA = connA.prepare(`select count(*) from auth_identities where id = 'blind-probe'`).pluck().get()
    connB.exec('rollback')

    expect(seenByB).toBe(1)
    // If this ever reads 1 the two handles have stopped being separate connections, and every other
    // assertion in this file goes quietly toothless.
    expect(seenByA).toBe(0)
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
