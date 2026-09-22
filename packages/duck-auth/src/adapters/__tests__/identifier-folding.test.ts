/**
 * One address, one row, whatever the client capitalised — held to the same answer on a store with a schema
 * and one without.
 *
 * The fold used to be the unique index's `lower()`, which is ASCII-only on sqlite: `lower('JOSÉ@x.test')`
 * answers `'JOSÉ@x.test'` there, where pg, mysql and `String.toLowerCase` fold the whole of Unicode. Since
 * sqlite's `create` leans on that index alone and runs no check first, one uppercase non-ascii letter was
 * enough for a row to be written that the index could not see was a duplicate and that `find` — which
 * lowercases in JS before it asks — could not match.
 */
import { beforeAll, describe, expect, it } from 'vitest'
import { DrizzleSqliteAdapter } from '~/adapters/drizzle/sqlite'
import { MemoryAdapter } from '~/adapters/memory'
import type { Identities } from '~/core/identities'
import { SQLITE_DDL as DDL } from '~/test/sqlite-schema'

type Profile = { username: string; email: string }
type Store = Identities.Store<Profile>

const IS_BUN = typeof (globalThis as { Bun?: unknown }).Bun !== 'undefined'

/** Both runtimes, as the compliance matrix does: bun:sqlite under bun, better-sqlite3 under node. */
async function sqliteStore(): Promise<Store> {
  if (IS_BUN) {
    const { Database } = (await import('bun:sqlite' as string)) as {
      Database: new (path: string) => { exec(sql: string): void }
    }
    const { drizzle } = await import('drizzle-orm/bun-sqlite')
    const db = new Database(':memory:')
    db.exec(DDL)
    // biome-ignore lint/suspicious/noExplicitAny: bun:sqlite Database is structurally the drizzle client.
    return new DrizzleSqliteAdapter<Profile>(drizzle(db as any)).identities
  }
  const { default: Database } = await import('better-sqlite3')
  const { drizzle } = await import('drizzle-orm/better-sqlite3')
  const db = new Database(':memory:')
  db.exec(DDL)
  // biome-ignore lint/suspicious/noExplicitAny: better-sqlite3 Database is structurally the drizzle client.
  return new DrizzleSqliteAdapter<Profile>(drizzle(db as any)).identities
}

const create = (store: Store, email: string, username: string) =>
  store.create({ emailVerified: false, profile: { email, username }, providers: [] })

/** The refusal's code, or `'ACCEPTED'` when the write went through. */
const outcome = async (fn: () => Promise<unknown>): Promise<string> =>
  fn()
    .then(() => 'ACCEPTED')
    .catch((err) => String((err as { code?: string }).code ?? err))

describe.each([
  ['drizzle-sqlite', sqliteStore],
  ['memory', async (): Promise<Store> => new MemoryAdapter<Profile>().identities],
])('%s folds an address the same way it looks one up', (_label, make) => {
  let store: Store
  beforeAll(async () => {
    store = await make()
  })

  it('stores the address in the spelling a lookup asks by', async () => {
    const row = await create(store, '  JOSÉ@x.test ', 'jose-stored')
    expect((row.profile as Profile).email).toBe('josé@x.test')
  })

  it('finds the row by the address as it was typed, and by its folded spelling', async () => {
    await create(store, 'ÉLODIE@x.test', 'elodie-found')
    await expect(store.find({ email: 'ÉLODIE@x.test' })).resolves.toMatchObject({ id: expect.any(String) })
    await expect(store.find({ email: 'élodie@x.test' })).resolves.toMatchObject({ id: expect.any(String) })
  })

  it('refuses a second row whose address differs only in the case of a non-ascii letter', async () => {
    await create(store, 'ÅSA@x.test', 'asa-first')
    expect(await outcome(() => create(store, 'åsa@x.test', 'asa-second'))).toBe('AUTH_EMAIL_TAKEN')
  })

  it('refuses one that differs only in ascii case, which is the control', async () => {
    // This case passed before the fix on every adapter, so it is what tells a real refusal above from a
    // store that has started refusing everything.
    await create(store, 'ASCII@x.test', 'ascii-first')
    expect(await outcome(() => create(store, 'ascii@x.test', 'ascii-second'))).toBe('AUTH_EMAIL_TAKEN')
  })

  it('still accepts a plainly different address, so the fold has not collapsed them all', async () => {
    expect(await outcome(() => create(store, 'unrelated@x.test', 'unrelated'))).toBe('ACCEPTED')
  })
})
