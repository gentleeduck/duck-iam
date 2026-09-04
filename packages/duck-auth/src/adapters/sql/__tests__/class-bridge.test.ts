import Database from 'better-sqlite3'
import { drizzle } from 'drizzle-orm/better-sqlite3'
import { describe, expect, it } from 'vitest'
import { createDrizzleSqliteBridge } from '~/adapters/drizzle/sqlite'
import { createSqlStores } from '~/adapters/sql'

type P = { username: string; email: string }

/**
 * `SqlBridge.*` are interfaces, so a caller may implement one as a class - or
 * as any object whose methods use `this`. Every shipped bridge is an object
 * literal of arrow functions, which hides a whole failure mode: hoisting an
 * optional bridge method into a local `const` to narrow it away from
 * `undefined` - `const { softDeleteManyReturningIds } = bridge` - detaches it
 * from its receiver, and the first `this` inside it throws or reads the wrong
 * object.
 *
 * These cases pin the receiver rather than the result. They deliberately apply
 * no schema: nothing here needs to reach the database, only to prove the call
 * arrives on the right object.
 */
const db = () => drizzle(new Database(':memory:'))

describe('a bridge whose methods use `this`', () => {
  it('has its optional batch method called with the bridge as receiver', async () => {
    const base = createDrizzleSqliteBridge<P>(db())
    const seen: string[] = []
    let receiver: unknown
    // Method shorthand, not an arrow: `this` is whatever the caller invoked it
    // on, which is exactly what a detached hoist gets wrong.
    const identities: typeof base.identities = {
      ...base.identities,
      async softDeleteManyReturningIds(ids: readonly string[], _deletedAt: Date) {
        receiver = this
        seen.push(...ids)
        return [...ids]
      },
    }

    const store = createSqlStores<P>({ ...base, identities }).identities
    const result = await store.softDeleteMany?.(['a', 'b'], 1000)

    expect(result?.applied).toBe(2)
    expect(seen).toEqual(['a', 'b'])
    expect(receiver).toBe(identities)
  })

  it('is true of the session and credential batch methods too', async () => {
    const base = createDrizzleSqliteBridge<P>(db())
    let sessionReceiver: unknown
    let credentialReceiver: unknown

    const sessions: typeof base.sessions = {
      ...base.sessions,
      async deleteAllForIdentitiesReturningIds(ids: readonly string[]) {
        sessionReceiver = this
        return [...ids]
      },
    }
    const credentials: typeof base.credentials = {
      ...base.credentials,
      async deleteByIdentitiesReturningIds(ids: readonly string[], _tenantId: string | undefined) {
        credentialReceiver = this
        return [...ids]
      },
    }

    const stores = createSqlStores<P>({ ...base, credentials, sessions })
    await stores.sessions.deleteAllForIdentities?.(['s1'])
    await stores.credentials.deleteByIdentities?.(['c1'], {})

    expect(sessionReceiver).toBe(sessions)
    expect(credentialReceiver).toBe(credentials)
  })
})
