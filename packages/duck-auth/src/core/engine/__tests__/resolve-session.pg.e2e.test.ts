/**
 * E2E: the resolution path against REAL Postgres, on the REAL shipped schema.
 *
 * `resolve-session-revocation.test.ts` drives the same rules with in-memory stores,
 * which proves the branching. It cannot prove that a soft-deleted identity is actually
 * invisible to the shipped query, because that lives in the adapter's WHERE clause.
 * A session outliving its account is the failure this file exists for.
 *
 * Skips when DUCKAUTH_E2E_DATABASE_URL is unset. See `.env.example`.
 */
import { createHash, randomUUID } from 'node:crypto'
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { drizzlePgStorage } from '~/adapters/drizzle/pg'
import { resolveBySid } from '~/core/sessions'
import { applyPgSchema, databaseUrl } from '~/test/e2e-env'

const URL = databaseUrl()
const suite = URL ? describe : describe.skip

suite('E2E resolveBySid on real Postgres', () => {
  let pool: Pool
  let stores: ReturnType<typeof drizzlePgStorage>
  let identityId: string

  /** Session ids are the sha-256 of the sid, and the column enforces 64 chars. */
  const sha256Hex = (value: string) => createHash('sha256').update(value).digest('hex')

  const mint = async (over: { identityId?: string | null; tenantId?: string | null } = {}) => {
    const sid = randomUUID()
    await stores.sessions.create({
      id: sha256Hex(sid),
      identityId: over.identityId === undefined ? identityId : over.identityId,
      tenantId: over.tenantId ?? null,
      kind: 'user',
      aal: 1,
      factors: [],
      csrfHash: null,
      ip: null,
      userAgent: null,
      fingerprint: null,
      createdAt: new Date(),
      rotatedAt: new Date(),
      expiresAt: new Date(Date.now() + 60_000),
      absoluteExpiresAt: new Date(Date.now() + 600_000),
      fresh: true,
      actingAs: null,
    })
    return sid
  }

  beforeAll(async () => {
    pool = new Pool({ connectionString: URL })
    await applyPgSchema(pool)
    stores = drizzlePgStorage(URL as string)

    identityId = randomUUID()
    await pool.query(
      `INSERT INTO auth_identities (id, profile, providers, version, email_verified, created_at, updated_at)
       VALUES ($1, $2::jsonb, '[]'::jsonb, 1, true, now(), now())`,
      [identityId, JSON.stringify({ email: 'e2e@resolve.test', username: 'e2e-resolve' })],
    )
  }, 60_000)

  afterAll(async () => {
    await pool.query('DELETE FROM auth_sessions WHERE identity_id = $1', [identityId])
    await pool.query('DELETE FROM auth_identities WHERE id = $1', [identityId])
    await pool.end()
  })

  it('resolves a live session with its identity attached', async () => {
    const sid = await mint()
    const resolved = await resolveBySid(sid, stores.sessions, stores.identities)
    expect(resolved?.identity?.id).toBe(identityId)
  })

  /**
   * The one the unit tests cannot prove: `findById` filters `deleted_at is null` in SQL,
   * so a soft delete has to make the identity invisible to the shipped query.
   */
  it('refuses a session whose identity was soft-deleted', async () => {
    const sid = await mint()
    await pool.query('UPDATE auth_identities SET deleted_at = now() WHERE id = $1', [identityId])
    try {
      await expect(resolveBySid(sid, stores.sessions, stores.identities)).rejects.toMatchObject({
        code: 'AUTH_SESSION_REVOKED',
      })
    } finally {
      await pool.query('UPDATE auth_identities SET deleted_at = NULL WHERE id = $1', [identityId])
    }
  })

  it('resolves again once the identity is restored', async () => {
    const sid = await mint()
    await pool.query('UPDATE auth_identities SET deleted_at = now() WHERE id = $1', [identityId])
    await pool.query('UPDATE auth_identities SET deleted_at = NULL WHERE id = $1', [identityId])
    await expect(resolveBySid(sid, stores.sessions, stores.identities)).resolves.toMatchObject({
      identity: { id: identityId },
    })
  })

  /** A guest session has no identity by design, so a null one here is not an erasure. */
  it('resolves a guest session with a null identity', async () => {
    const sid = await mint({ identityId: null })
    const resolved = await resolveBySid(sid, stores.sessions, stores.identities)
    expect(resolved).toMatchObject({ identity: null })
    expect(resolved?.session.identityId).toBeNull()
  })

  /** Tenant before identity: a foreign token looks absent rather than reporting an erasure. */
  it('returns null for a foreign tenant', async () => {
    const sid = await mint({ tenantId: 'tenant-a' })
    await expect(
      resolveBySid(sid, stores.sessions, stores.identities, { expectedTenantId: 'tenant-b' }),
    ).resolves.toBeNull()
  })

  it('returns null for a foreign tenant even when the identity is erased', async () => {
    const sid = await mint({ tenantId: 'tenant-a' })
    await pool.query('UPDATE auth_identities SET deleted_at = now() WHERE id = $1', [identityId])
    try {
      await expect(
        resolveBySid(sid, stores.sessions, stores.identities, { expectedTenantId: 'tenant-b' }),
      ).resolves.toBeNull()
    } finally {
      await pool.query('UPDATE auth_identities SET deleted_at = NULL WHERE id = $1', [identityId])
    }
  })

  it('returns null and deletes the row for an expired session', async () => {
    const sid = await mint()
    const id = sha256Hex(sid)
    // Both timestamps move: `chk_auth_sessions_expires_after_created` rejects an expiry
    // that precedes creation, so backdating only `expires_at` violates the constraint.
    await pool.query(
      `UPDATE auth_sessions
         SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 minute'
       WHERE id = $1`,
      [id],
    )

    await expect(resolveBySid(sid, stores.sessions, stores.identities)).resolves.toBeNull()
    const { rows } = await pool.query('SELECT 1 FROM auth_sessions WHERE id = $1', [id])
    expect(rows).toHaveLength(0)
  })

  it('an unknown sid resolves to null rather than throwing', async () => {
    await expect(resolveBySid(randomUUID(), stores.sessions, stores.identities)).resolves.toBeNull()
  })

  /** What the app does on account deletion: kill the sessions, then erase the row. */
  it('deleteAllForIdentity leaves nothing resolvable', async () => {
    const first = await mint()
    const second = await mint()
    await stores.sessions.deleteAllForIdentity(identityId)

    await expect(resolveBySid(first, stores.sessions, stores.identities)).resolves.toBeNull()
    await expect(resolveBySid(second, stores.sessions, stores.identities)).resolves.toBeNull()
  })
})
