/**
 * E2E: the SQL session store against REAL Postgres, on the REAL shipped schema.
 *
 * The sqlite conformance run already covers the `sql.ts` bridge's logic. What it
 * cannot cover is the actual production dialect: `timestamptz`, `jsonb`, `uuid`
 * identity ids, and the `ON DELETE CASCADE` foreign key to `auth_identities`.
 * Those only exist here.
 *
 * The suite creates the shipped schema itself (generated from the drizzle pg
 * schema), so it runs against exactly what ships and never touches app data.
 *
 * Skips when DUCKAUTH_E2E_DATABASE_URL is unset. See `.env.example`.
 */
import { createHash, randomUUID } from 'node:crypto'
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { applyPgSchema, databaseUrl } from '~/test/e2e-env'

const URL = databaseUrl()
const suite = URL ? describe : describe.skip

suite('E2E sessions on real Postgres (shipped schema)', () => {
  let pool: Pool
  let identityId: string

  /** Insert a session row directly — this suite tests the schema and dialect,
   *  not the drizzle wiring, which sqlite conformance already covers. */
  /** Session ids must be exactly 64 chars — `chk_auth_sessions_id_length`. */
  function sid(): string {
    return createHash('sha256').update(randomUUID()).digest('hex')
  }

  async function insertSession(over: Partial<Record<string, unknown>> = {}): Promise<string> {
    const id = (over.id as string) ?? sid()
    const now = new Date()
    await pool.query(
      `INSERT INTO auth_sessions
        (id, identity_id, tenant_id, kind, aal, factors, csrf_hash, ip, user_agent,
         fingerprint, created_at, rotated_at, expires_at, absolute_expires_at, fresh, acting_as)
       VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb)`,
      [
        id,
        over.identity_id ?? identityId,
        null,
        'user',
        over.aal ?? 1,
        JSON.stringify(over.factors ?? []),
        null,
        null,
        null,
        null,
        now,
        now,
        over.expires_at ?? new Date(now.getTime() + 60_000),
        over.absolute_expires_at ?? new Date(now.getTime() + 86_400_000),
        over.fresh ?? true,
        null,
      ],
    )
    return id
  }

  beforeAll(async () => {
    pool = new Pool({ connectionString: URL as string, max: 10 })
    await applyPgSchema(pool)
    identityId = randomUUID()
    await pool.query(
      `INSERT INTO auth_identities (id, profile, providers, version, email_verified, created_at, updated_at)
       VALUES ($1, $2::jsonb, $3::jsonb, 1, true, now(), now())`,
      [identityId, JSON.stringify({ username: 'e2e', email: 'e2e@test.local' }), JSON.stringify([])],
    )
  }, 30_000)

  afterAll(async () => {
    if (pool) {
      // FK is ON DELETE CASCADE, so this clears the sessions too.
      await pool.query('DELETE FROM auth_identities WHERE id = $1', [identityId])
      await pool.end()
    }
  })

  describe('dialect behaviour the sqlite suite cannot reach', () => {
    it('round-trips timestamptz without drifting', async () => {
      const exact = new Date(Date.now() + 3_600_000 + 789 - (Date.now() % 1000))
      const id = await insertSession({ expires_at: exact })
      const { rows } = await pool.query('SELECT expires_at FROM auth_sessions WHERE id = $1', [id])
      expect((rows[0].expires_at as Date).toISOString()).toBe(exact.toISOString())
    })

    it('round-trips a jsonb factors array', async () => {
      const factors = [{ method: 'password', completedAt: new Date().toISOString() }]
      const id = await insertSession({ factors })
      const { rows } = await pool.query('SELECT factors FROM auth_sessions WHERE id = $1', [id])
      expect(rows[0].factors).toEqual(factors)
    })

    it('rejects a non-uuid identity_id — the column type is a real constraint', async () => {
      await expect(insertSession({ identity_id: 'not-a-uuid' })).rejects.toThrow()
    })

    it('CASCADE deletes sessions when the identity is erased', async () => {
      const doomedIdentity = randomUUID()
      await pool.query(
        `INSERT INTO auth_identities (id, profile, providers, version, email_verified, created_at, updated_at)
         VALUES ($1, $2::jsonb, '[]'::jsonb, 1, true, now(), now())`,
        [doomedIdentity, JSON.stringify({ username: 'doomed', email: 'd@test.local' })],
      )
      await insertSession({ identity_id: doomedIdentity })

      await pool.query('DELETE FROM auth_identities WHERE id = $1', [doomedIdentity])

      const { rows } = await pool.query('SELECT count(*)::int AS n FROM auth_sessions WHERE identity_id = $1', [
        doomedIdentity,
      ])
      // Confirms C1 finding #12's premise: an erased identity really does leave
      // no session rows behind on Postgres.
      expect(rows[0].n).toBe(0)
    })
  })

  describe('CHECK constraints that ONLY Postgres enforces', () => {
    // The sqlite conformance DDL says in its own comment that it "intentionally
    // omits CHECK constraints". Memory and Redis have no schema at all. So these
    // eight invariants are enforced in production and nowhere else — a write the
    // library considers valid can still be rejected by the real database.

    it('rejects a session id that is not exactly 64 chars (sha-256 hex)', async () => {
      // Memory, Redis and sqlite all accept any string as an id.
      await expect(insertSession({ id: 'short-id' })).rejects.toThrow(/chk_auth_sessions_id_length/)
    })

    it('rejects absoluteExpiresAt earlier than expiresAt', async () => {
      const now = Date.now()
      await expect(
        insertSession({
          expires_at: new Date(now + 86_400_000),
          absolute_expires_at: new Date(now + 60_000),
        }),
      ).rejects.toThrow(/absolute_expires_after_expires/)
    })

    it('rejects an out-of-range aal', async () => {
      await expect(insertSession({ aal: 9 })).rejects.toThrow(/chk_auth_sessions_aal/)
    })

    it('rejects an identity profile without BOTH username and email', async () => {
      // This is the one that bites: `beginSignUp` builds its profile as
      // `{ ...initialProfile, email, emailVerified }` — no `username` unless the
      // caller supplies one. On this schema that INSERT fails.
      const id = randomUUID()
      await expect(
        pool.query(
          `INSERT INTO auth_identities (id, profile, providers, version, email_verified, created_at, updated_at)
           VALUES ($1, $2::jsonb, '[]'::jsonb, 1, false, now(), now())`,
          [id, JSON.stringify({ email: 'no-username@test.local', emailVerified: false })],
        ),
      ).rejects.toThrow(/chk_auth_identities_profile_shape/)
    })
  })

  describe('R1 lost update — does Postgres behave like Redis?', () => {
    it('two concurrent partial UPDATEs both apply (unlike Redis)', async () => {
      const id = await insertSession()

      // The SQL bridge issues a single UPDATE per patch, touching only the
      // columns in that patch — no read-modify-write, so no lost update.
      await Promise.all([
        pool.query('UPDATE auth_sessions SET aal = $1 WHERE id = $2', [2, id]),
        pool.query('UPDATE auth_sessions SET fresh = $1 WHERE id = $2', [false, id]),
      ])

      const { rows } = await pool.query('SELECT aal, fresh FROM auth_sessions WHERE id = $1', [id])
      const bothApplied = rows[0].aal === 2 && rows[0].fresh === false

      // Redis lost a write 40/40. Postgres should lose none — a cross-store
      // divergence in a security-relevant path.
      expect(bothApplied).toBe(true)
    })
  })

  describe('performance at scale', () => {
    it('measures listByIdentity and gc over 2000 rows', async () => {
      const bulkIdentity = randomUUID()
      await pool.query(
        `INSERT INTO auth_identities (id, profile, providers, version, email_verified, created_at, updated_at)
         VALUES ($1, $2::jsonb, '[]'::jsonb, 1, true, now(), now())`,
        [bulkIdentity, JSON.stringify({ username: 'bulk', email: 'b@test.local' })],
      )

      const now = Date.now()
      const values: string[] = []
      const params: unknown[] = []
      for (let i = 0; i < 2000; i++) {
        const b = i * 6
        values.push(
          `($${b + 1},$${b + 2},'user',1,'[]'::jsonb,to_timestamp($${b + 3}),to_timestamp($${b + 4}),to_timestamp($${b + 5}),to_timestamp($${b + 6}),true)`,
        )
        // Half already expired, so gc has real work to do.
        const expired = i % 2 === 0
        const exp = (expired ? now - 60_000 : now + 60_000) / 1000
        const created = expired ? now - 120_000 : now
        params.push(sid(), bulkIdentity, created / 1000, created / 1000, exp, exp)
      }
      await pool.query(
        `INSERT INTO auth_sessions
           (id, identity_id, kind, aal, factors, created_at, rotated_at, expires_at, absolute_expires_at, fresh)
         VALUES ${values.join(',')}`,
        params,
      )

      const t1 = Date.now()
      const listed = await pool.query('SELECT * FROM auth_sessions WHERE identity_id = $1', [bulkIdentity])
      const listMs = Date.now() - t1

      const t2 = Date.now()
      const gc = await pool.query('DELETE FROM auth_sessions WHERE expires_at < now() OR absolute_expires_at < now()')
      const gcMs = Date.now() - t2

      await pool.query('DELETE FROM auth_identities WHERE id = $1', [bulkIdentity])

      // Postgres does this set-based in one statement; Redis needs N+1 round
      // trips for the same work (S3/S4).
      expect(listed.rowCount).toBe(2000)
      expect(gc.rowCount).toBeGreaterThan(0)
      expect(listMs).toBeLessThan(5000)
      expect(gcMs).toBeLessThan(5000)
    }, 60_000)
  })
})
