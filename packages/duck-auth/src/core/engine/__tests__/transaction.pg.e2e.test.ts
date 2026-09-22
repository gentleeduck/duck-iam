/** E2E: `withTransaction` against REAL Postgres on the REAL shipped schema. */
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { DrizzlePgAdapter } from '~/adapters/drizzle/pg'
import { sha256 } from '~/core/crypto'
import { AuthEngine } from '~/core/engine'
import type { Events } from '~/core/events'
import { InMemoryEvents } from '~/core/events'
import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'
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
      stores: new DrizzlePgAdapter(db),
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
    let pending: { flush(): Promise<{ published: number }> } | undefined

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
      await expect(auth.identities.getById(created.id)).resolves.toBeDefined()
      // ...and invisible on the engine's own connection.
      await expect(engine.identities.getById(created.id)).rejects.toMatchObject({
        code: 'AUTH_IDENTITY_NOT_FOUND',
      })
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
    // completeAccountDeletion touches five things: it rotates the recovery
    // credential, soft-deletes the identity, sweeps the sessions, deletes the
    // credential, then mints the undo token. All five must land on the caller's
    // tx, not just the first.
    const identity = await engine.identities.create({ profile: { email: 'del@x', username: 'del' } })
    await engine.sessions.create({ aal: 1, factors: [], identityId: identity.id, kind: 'user' })

    const token = 'deletion-token-for-test'
    await engine.cfg.stores.credentials.create(
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

      // Inside the tx: identity soft-deleted, so a live lookup misses; the
      // deletion token is gone and the undo token is the only `recovery` row
      // left. Writes two, four and five of the nested call all landed on the
      // caller's transaction, not just the first.
      await expect(auth.identities.getById(identity.id)).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
      const rows = await auth.stores.credentials.listByIdentity(identity.id, 'recovery', {})
      expect(rows.map((r) => (r.metadata as { purpose?: string } | null)?.purpose)).toEqual(['account-deletion-cancel'])
    })

    // After rollback everything is back, and nothing was published.
    await expect(engine.identities.getById(identity.id)).resolves.toBeDefined()
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

  it('one bad row rolls the whole batch back', async () => {
    const a = await engine.identities.create({ profile: { email: 'ba@x', username: 'ba' } })
    const b = await engine.identities.create({ profile: { email: 'bb@x', username: 'bb' } })
    // The address the bad row will collide with. `auth_identities` carries a
    // unique index on lower(profile->>'email'), so this is a hard constraint
    // violation - the kind that must abort the caller's transaction rather than
    // be reported as a per-row miss.
    await engine.identities.create({ profile: { email: 'taken@x', username: 'taken' } })
    published = []

    const failure = await db
      .transaction(async (tx) => {
        const auth = engine.withTransaction(tx)
        await auth.identities.updateProfileMany([
          { expectedVersion: b.version, id: b.id, patch: { username: 'bb2' } },
          { expectedVersion: a.version, id: a.id, patch: { email: 'taken@x' } },
        ])
      })
      .then(
        () => null,
        (err: unknown) => err,
      )

    // Pinned to the constraint, so the case cannot start passing on some
    // unrelated throw - a cap check, a typo'd id - and quietly stop testing
    // atomicity. The index violation now arrives as the typed error rather than
    // a raw driver one, and it still aborts: a hard failure, not a per-row miss.
    expect(failure).toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
    // The driver's own message stays reachable underneath, so the typed code is
    // a rename and not a swallow. It sits two levels down - drizzle wraps the
    // pg error in its own "Failed query" one - which is why the mapping walks
    // the whole chain rather than reading `cause` once.
    let detail = ''
    for (let err: unknown = failure; err instanceof Error; err = err.cause) detail += ` ${err.message}`
    expect(detail).toMatch(/duplicate key|unique/i)

    // The good row from the same batch is gone too - that is what atomic means.
    expect((await engine.identities.getById(b.id)).profile.username).toBe('bb')
    expect((await engine.identities.getById(a.id)).profile.email).toBe('ba@x')
    expect(published).toEqual([])
  })

  it('a soft failure does not roll the batch back', async () => {
    const a = await engine.identities.create({ profile: { email: 'sa@x', username: 'sa' } })
    const b = await engine.identities.create({ profile: { email: 'sb@x', username: 'sb' } })

    let result: Identities.Me<P>[] | undefined
    await db.transaction(async (tx) => {
      const auth = engine.withTransaction(tx)
      result = await auth.identities.updateProfileMany([
        // Stale - a soft failure, so the row is left out rather than taking the batch with it.
        { expectedVersion: 999, id: a.id, patch: { username: 'sa2' } },
        { expectedVersion: b.version, id: b.id, patch: { username: 'sb2' } },
      ])
    })

    expect(result?.map((row) => row.id)).toEqual([b.id])
    // The commit stood: b was updated, a was not.
    expect((await engine.identities.getById(b.id)).profile.username).toBe('sb2')
    expect((await engine.identities.getById(a.id)).profile.username).toBe('sa')
  })

  it('a bulk revoke reports which identities had no sessions', async () => {
    const a = await engine.identities.create({ profile: { email: 'ra@x', username: 'ra' } })
    const b = await engine.identities.create({ profile: { email: 'rb@x', username: 'rb' } })
    await engine.sessions.create({ aal: 1, factors: [], identityId: a.id, kind: 'user' })
    published = []

    let result: Sessions.Revoked[] | undefined
    let pending: { flush(): Promise<{ published: number }> } | undefined
    await db.transaction(async (tx) => {
      const auth = engine.withTransaction(tx)
      result = await auth.sessions.revokeAllForIdentities([a.id, b.id])
      pending = auth.pending
    })
    await pending?.flush()

    // Only the identity that had one comes back; the other is simply absent.
    expect(result?.map((s) => s.identityId)).toEqual([a.id])
    // One session existed, so exactly one revocation event - not two, and not
    // one per identity named.
    expect(published.filter((e) => e === 'session.revoked')).toHaveLength(1)
  })

  it('the unbound engine still commits on its own and emits immediately', async () => {
    published = []
    await engine.identities.create({ profile: { email: 'plain@x', username: 'plain' } })

    expect(await count('auth_identities')).toBe(1)
    expect(published).toEqual(['signup.completed'])
  })
})
