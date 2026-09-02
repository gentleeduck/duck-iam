/**
 * E2E: `withTransaction` against REAL Postgres on the REAL shipped schema.
 *
 * The in-process tests prove the wiring - that stores get re-bound and events
 * get buffered. Only a real transaction can prove the thing that matters: that
 * a rollback leaves no row AND publishes no event, that a read inside the
 * transaction sees its own uncommitted writes, and that a nested flow call
 * inherits the caller's transaction across every write it makes.
 *
 * Uses an isolated database because it truncates between cases; vitest runs
 * files in parallel workers, so a shared database would let one suite's
 * TRUNCATE land in the middle of another's fixtures.
 *
 * Skips when DUCKAUTH_E2E_DATABASE_URL is unset; `globalSetup` provisions a
 * container when docker is available.
 */
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { createDrizzlePgBridge } from '~/adapters/drizzle/pg'
import { createSqlStores } from '~/adapters/sql'
import { sha256 } from '~/core/crypto'
import { AuthEngine } from '~/core/engine'
import type { Events } from '~/core/events'
import { InMemoryEvents } from '~/core/events'
import type { Identities } from '~/core/identities/identities.types'
import { BearerTransport } from '~/core/transport/bearer.transport'
import { apiKeyProvider } from '~/providers/api-key'
import { mfaProvider } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { applyPgSchema, isolatedDatabaseUrl } from '~/test/e2e-env'

const URL = await isolatedDatabaseUrl('tx_participation')
const suite = URL ? describe : describe.skip

type P = Identities.ProfileMetadataBase

const WATCHED = [
  'signup.completed',
  'session.created',
  'session.revoked',
  'identity.linked',
  'mfa.enrolled',
  'mfa.removed',
] as const satisfies readonly Events.EventName[]

suite('E2E withTransaction on real Postgres', () => {
  let pool: Pool
  let db: ReturnType<typeof drizzle>
  let engine: AuthEngine<P>
  let published: string[]

  beforeAll(async () => {
    pool = new Pool({ connectionString: URL })
    await applyPgSchema(pool)
    db = drizzle(pool)
  })

  afterAll(async () => {
    await pool.end()
  })

  beforeEach(async () => {
    await pool.query('TRUNCATE auth_sessions, auth_credentials, auth_identities CASCADE')
    published = []
    const bus = new InMemoryEvents()
    for (const name of WATCHED) {
      bus.on(name, async () => {
        published.push(name)
      })
    }
    engine = new AuthEngine<P>({
      baseUrl: 'http://localhost:0',
      events: bus,
      providers: [passwords({ hasher: new ScryptHasher() }), mfaProvider(), apiKeyProvider()],
      stores: createSqlStores<P>(createDrizzlePgBridge<P>(db)),
      transport: new BearerTransport(),
    })
  })

  async function count(table: string, where = ''): Promise<number> {
    const r = await pool.query(`SELECT count(*)::int AS n FROM ${table} ${where}`)
    return (r.rows[0] as { n: number }).n
  }

  /**
   * Runs `body` on a transaction that always rolls back, and re-throws anything
   * the body threw that is not our own sentinel.
   *
   * A bare `.catch(() => {})` around the transaction would swallow the `expect()`
   * failures inside the body *and* the real error that caused them, leaving a
   * test that passes because nothing happened at all. Rolling back is the point
   * here; silently skipping the work is not.
   */
  async function rollsBack(body: (tx: unknown) => Promise<void>): Promise<void> {
    const sentinel = new Error('__rollback__')
    await db
      .transaction(async (tx) => {
        await body(tx)
        throw sentinel
      })
      .catch((err: unknown) => {
        if (err !== sentinel) throw err
      })
  }

  it('rollback leaves no identity row and publishes no event', async () => {
    await expect(
      db.transaction(async (tx) => {
        const auth = engine.withTransaction(tx)
        await auth.identities.create({ profile: { email: 'rb@x', username: 'rb' } })
        expect(auth.pending.size).toBe(1)
        throw new Error('force rollback')
      }),
    ).rejects.toThrow('force rollback')

    expect(await count('auth_identities')).toBe(0)
    expect(published).toEqual([])
  })

  it('commit keeps the row, and flush publishes only then', async () => {
    let pending: { flush(): Promise<void> } | undefined

    await db.transaction(async (tx) => {
      const auth = engine.withTransaction(tx)
      await auth.identities.create({ profile: { email: 'ok@x', username: 'ok' } })
      pending = auth.pending
    })

    expect(await count('auth_identities')).toBe(1)
    expect(published).toEqual([])

    await pending?.flush()
    expect(published).toEqual(['signup.completed'])
  })

  it('a read inside the transaction sees the transaction own uncommitted write', async () => {
    await rollsBack(async (tx) => {
      const auth = engine.withTransaction(tx)
      const created = await auth.identities.create({ profile: { email: 'rd@x', username: 'rd' } })

      // Visible on the transaction...
      expect(await auth.identities.getById(created.id)).not.toBeNull()
      // ...and invisible on the engine's own connection.
      expect(await engine.identities.getById(created.id)).toBeNull()
    })
  })

  it('sessions rollback leaves no session row and publishes no event', async () => {
    const identity = await engine.identities.create({ profile: { email: 's@x', username: 's' } })
    published = []

    await rollsBack(async (tx) => {
      const auth = engine.withTransaction(tx)
      await auth.sessions.create({ aal: 1, factors: [], identityId: identity.id, kind: 'user' })
    })

    expect(await count('auth_sessions')).toBe(0)
    expect(published).toEqual([])
  })

  it('a nested flow call inherits the caller transaction across all of its writes', async () => {
    // completeAccountDeletion touches four things: it rotates the recovery
    // credential, soft-deletes the identity, sweeps the sessions, then deletes
    // the credential. All four must land on the caller's tx, not just the first.
    const identity = await engine.identities.create({ profile: { email: 'del@x', username: 'del' } })
    await engine.sessions.create({ aal: 1, factors: [], identityId: identity.id, kind: 'user' })

    const token = 'deletion-token-for-test'
    await engine.cfg.stores.credentials.upsert(
      {
        expiresAt: new Date(Date.now() + 600_000),
        identityId: identity.id,
        kind: 'recovery',
        lastUsedAt: null,
        metadata: { purpose: 'account-deletion' },
        revokedAt: null,
        secret: sha256(token),
        tenantId: null,
      },
      {},
    )
    published = []

    await rollsBack(async (tx) => {
      const auth = engine.withTransaction(tx)
      await auth.flows.completeAccountDeletion({ token })

      // Inside the tx: identity soft-deleted, so a live lookup misses, and the
      // credential the flow deleted is gone too. Both prove writes two and four
      // of the nested call landed on the caller's transaction, not just the first.
      expect(await auth.identities.getById(identity.id)).toBeNull()
      expect(await auth.stores.credentials.listByIdentity(identity.id, 'recovery', {})).toEqual([])
    })

    // After rollback everything is back, and nothing was published.
    expect(await engine.identities.getById(identity.id)).not.toBeNull()
    expect(await count('auth_sessions')).toBe(1)
    expect(await count('auth_credentials', "WHERE kind = 'recovery'")).toBe(1)
    expect(published).toEqual([])
  })

  it('mfa rollback leaves no credential row and publishes no event', async () => {
    const identity = await engine.identities.create({ profile: { email: 'mfa@x', username: 'mfa' } })
    published = []

    await rollsBack(async (tx) => {
      const auth = engine.withTransaction(tx)
      await auth.mfa.beginTotpEnrollment(identity.id, 'mfa@x')
      await auth.mfa.removeTotp(identity.id)
      expect(auth.pending.size).toBeGreaterThan(0)
    })

    expect(await count('auth_credentials', "WHERE kind = 'totp'")).toBe(0)
    expect(published).toEqual([])
  })

  it('apiKeys rollback leaves no credential row', async () => {
    const identity = await engine.identities.create({ profile: { email: 'ak@x', username: 'ak' } })

    await rollsBack(async (tx) => {
      const auth = engine.withTransaction(tx)
      await auth.apiKeys.create(identity.id, { name: 'k', scopes: ['read'] })
    })

    expect(await count('auth_credentials', "WHERE kind = 'api-key'")).toBe(0)
  })

  it('the unbound engine still commits on its own and emits immediately', async () => {
    published = []
    await engine.identities.create({ profile: { email: 'plain@x', username: 'plain' } })

    expect(await count('auth_identities')).toBe(1)
    expect(published).toEqual(['signup.completed'])
  })
})
