/**
 * The drizzle pg adapter itself, against REAL Postgres.
 *
 * The compliance matrix covers what every adapter must agree on; these are the pg specifics under it - the
 * folded read, the CTE writes, and a typed error for every constraint the shipped schema declares.
 *
 * Skips when DUCKAUTH_E2E_DATABASE_URL is unset; `globalSetup` provisions a container when docker is there.
 */
import { createHash } from 'node:crypto'
import { sql } from 'drizzle-orm'
import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres'
import { getTableConfig } from 'drizzle-orm/pg-core'
import { Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import type { Adapter } from '~/adapters/adapter'
import { withActor } from '~/core/actor'
import type { Credential } from '~/core/credentials/credentials.types'
import { authUuidV7 } from '~/core/crypto'
import type { AuthError } from '~/core/errors'
import { sqlError } from '~/core/errors'
import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'
import { applyPgSchema, databaseUrl, isolatedDatabaseUrl } from '~/test/e2e-env'
import { authCredentials, authIdentities, authIdentityProviders, authSessions, DrizzlePgAdapter } from '../index'

const URL = databaseUrl()
const suite = URL ? describe : describe.skip

type Profile = { username: string; email: string }
type CreateInput = Identities.CreateInput<Profile>

/** `auth_identities.id` is `uuid`, and everything else carries an FK to it. */
const OWNER = authUuidV7()
/** `chk_auth_sessions_id_length` demands exactly 64 chars, as every real sid is. */
const sid = (label: string) => createHash('sha256').update(label).digest('hex')
const ago = (ms: number) => new Date(Date.now() - ms)
const ahead = (ms: number) => new Date(Date.now() + ms)
const GRACE = 60_000
const anywhere = { tenantId: undefined }

/** Runs a raw statement the way an adapter call runs it, so it answers the same typed error. */
async function attempt(query: () => Promise<unknown>): Promise<{ error: AuthError | null }> {
  try {
    await query()
    return { error: null }
  } catch (err) {
    return { error: sqlError(err) }
  }
}

/** The constraint postgres named, down the cause chain the typed error kept. */
function constraintOf(err: unknown): unknown {
  let cur = err
  while (typeof cur === 'object' && cur !== null) {
    if ('constraint' in cur && cur.constraint !== undefined) return cur.constraint
    cur = 'cause' in cur ? cur.cause : null
  }
  return undefined
}

function identity(name: string, over: Partial<CreateInput> = {}): CreateInput {
  return {
    emailVerified: false,
    profile: { email: `${name}@adapter.test`, username: name },
    providers: [],
    ...over,
  }
}

/** The insert shape the table takes, for the rows a store API cannot produce. */
function row(name: string, over: Partial<Identities.Me<Profile>> = {}) {
  return { ...identity(name), createdBy: null, deletedAt: null, deletedBy: null, updatedBy: null, ...over }
}

function credential(identityId: string, over: Partial<Credential.UpsertInput> = {}): Credential.UpsertInput {
  return {
    expiresAt: null,
    identityId,
    kind: 'password',
    lastUsedAt: null,
    metadata: null,
    revokedAt: null,
    secret: 'hash',
    tenantId: null,
    ...over,
  }
}

function session(label: string, over: Partial<Sessions.Me> = {}): Sessions.Me {
  const at = new Date()
  return {
    aal: 1,
    absoluteExpiresAt: new Date(at.getTime() + 600_000),
    actingAs: null,
    createdAt: at,
    csrfHash: null,
    expiresAt: new Date(at.getTime() + 60_000),
    factors: [],
    fingerprint: null,
    fresh: true,
    id: sid(label),
    identityId: OWNER,
    ip: null,
    kind: 'user',
    rotatedAt: at,
    tenantId: null,
    userAgent: null,
    ...over,
  }
}

suite('drizzle pg adapter (real Postgres)', () => {
  let pool: Pool
  let db: NodePgDatabase
  let adapter: Adapter.Me<Profile>

  beforeAll(async () => {
    // Owned database: this suite truncates between cases, and the other pg suites run in parallel
    // workers against the shared one.
    const own = await isolatedDatabaseUrl('pg_adapter')
    pool = new Pool({ connectionString: own })
    await applyPgSchema(pool)
    db = drizzle(pool)
    adapter = new DrizzlePgAdapter(db)
  }, 60_000)

  afterAll(async () => {
    await pool?.end()
  })

  beforeEach(async () => {
    await pool.query('TRUNCATE auth_sessions, auth_credentials, auth_identities CASCADE')
    await pool.query(`INSERT INTO auth_identities (id, profile) VALUES ($1, $2::jsonb)`, [
      OWNER,
      JSON.stringify({ email: 'owner@adapter.test', username: 'owner' }),
    ])
  })

  describe('identities', () => {
    it('leaves the id, the version and the timestamps to the schema', async () => {
      const created = await adapter.identities.create(identity('fresh'))

      expect(created.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
      expect(created).toMatchObject({ version: 1 })
      expect(created.createdAt).toBeInstanceOf(Date)
    })

    it('stamps who wrote the row, and who hid it', async () => {
      const created = await withActor('op-1', () => adapter.identities.create(identity('stamps')))

      expect(created).toMatchObject({ createdBy: 'op-1', updatedBy: 'op-1' })
      expect(await withActor('op-2', () => adapter.identities.softDelete(created.id, GRACE))).toMatchObject({
        deletedBy: 'op-2',
      })
    })

    it('finds a live row by id, by email in any case, or by provider sub', async () => {
      const addedAt = new Date('2026-01-02T03:04:05.000Z')
      const created = await adapter.identities.create(
        identity('find', { providers: [{ addedAt, providerId: 'google', providerSub: 'g-find' }] }),
      )

      expect((await adapter.identities.find({ id: created.id }))?.id).toBe(created.id)
      expect((await adapter.identities.find({ email: 'FIND@Adapter.test' }))?.id).toBe(created.id)
      const byProvider = await adapter.identities.find({ providerId: 'google', providerSub: 'g-find' })
      expect(byProvider?.id).toBe(created.id)
      expect(byProvider?.providers[0]?.addedAt.getTime()).toBe(addedAt.getTime())
    })

    it('leaves addedAt to the link table when the caller names none', async () => {
      const created = await adapter.identities.create(
        identity('stamped', { providers: [{ providerId: 'google', providerSub: 'g-stamped' }] }),
      )

      expect(created.providers[0]?.addedAt).toBeInstanceOf(Date)
    })

    it('misses a hidden row, an unknown id, and an empty email', async () => {
      const created = await adapter.identities.create(identity('hidden'))
      await adapter.identities.softDelete(created.id, GRACE)

      expect(await adapter.identities.find({ id: created.id })).toBeNull()
      expect(await adapter.identities.find({ email: 'hidden@adapter.test' })).toBeNull()
      expect(await adapter.identities.find({ id: authUuidV7() })).toBeNull()
      expect(await adapter.identities.find({ email: '' })).toBeNull()
    })

    // An id the `uuid` column cannot hold is postgres's to refuse, not something the adapter reads as a miss.
    it('hands back what postgres says about an id it cannot cast', async () => {
      await expect(adapter.identities.find({ id: 'not-a-uuid' })).rejects.toMatchObject({
        code: 'AUTH_INVALID_PARAMETERS',
      })
      await expect(adapter.identities.erase('not-a-uuid')).rejects.toMatchObject({
        code: 'AUTH_INVALID_PARAMETERS',
      })
    })

    it('writes each row against its own version, and refuses one that lost the race', async () => {
      const a = await adapter.identities.create(identity('ver-a'))

      const updated = await adapter.identities.update(
        a.id,
        { profile: { email: 'ver-a@adapter.test', username: 'ver-a2' } },
        1,
      )
      expect(updated).toMatchObject({ profile: { username: 'ver-a2' }, version: 2 })

      for (const id of [a.id, authUuidV7()]) {
        await expect(adapter.identities.update(id, { emailVerified: true }, 1)).rejects.toMatchObject({
          code: 'AUTH_STALE_WRITE',
        })
      }
      expect(await adapter.identities.find({ id: a.id })).toMatchObject({ emailVerified: false, version: 2 })
    })

    it('writes nothing of an update that would take a live address', async () => {
      const a = await adapter.identities.create(identity('clash-a'))

      await expect(
        adapter.identities.update(a.id, { profile: { email: 'OWNER@adapter.test', username: 'clash-a' } }, 1),
      ).rejects.toMatchObject({ code: 'AUTH_EMAIL_TAKEN' })
      expect(await adapter.identities.find({ id: a.id })).toMatchObject({ version: 1 })
    })

    it('hides a live row once, clearing emailVerified, keeping its links', async () => {
      const link = { addedAt: new Date(), providerId: 'google', providerSub: 'g-gone' }
      const created = await adapter.identities.create(identity('gone', { emailVerified: true, providers: [link] }))

      const hidden = await adapter.identities.softDelete(created.id, GRACE)
      expect(hidden).toMatchObject({ emailVerified: false, id: created.id })
      expect(hidden?.providers).toHaveLength(1)
      // Re-stamping would push the purge deadline forward on every repeat.
      expect(await adapter.identities.softDelete(created.id, 120_000)).toBeNull()
    })

    it('erase takes the row credentials, sessions and links with it', async () => {
      const link = { addedAt: new Date(), providerId: 'google', providerSub: 'g-erase' }
      const created = await adapter.identities.create(identity('erase', { providers: [link] }))
      await adapter.credentials.upsert(credential(created.id), anywhere)
      await adapter.sessions.create(session('erase', { identityId: created.id }))

      // The links come back on the erased row, read while they were still there.
      expect((await adapter.identities.erase(created.id))?.providers).toHaveLength(1)
      expect(await adapter.credentials.listByIdentity(created.id, null, anywhere)).toEqual([])
      expect(await adapter.sessions.getByHash(sid('erase'))).toBeNull()
      expect(await adapter.identities.erase(authUuidV7())).toBeNull()
    })

    it('restores a row inside its window, and names why one outside it stayed hidden', async () => {
      const ok = await adapter.identities.create(identity('ok'))
      await adapter.identities.softDelete(ok.id, GRACE)
      const expired = await adapter.identities.create(identity('expired'))
      await adapter.identities.softDelete(expired.id, -1000)

      expect(await adapter.identities.restore(ok.id)).toMatchObject({ deletedAt: null, deletedBy: null })
      expect((await adapter.identities.find({ id: ok.id }))?.id).toBe(ok.id)
      await expect(adapter.identities.restore(expired.id)).rejects.toMatchObject({ code: 'AUTH_GRACE_EXPIRED' })
      expect(await adapter.identities.restore(authUuidV7())).toBeNull()
      // A live row restores to itself rather than being refused.
      expect((await adapter.identities.restore(ok.id))?.id).toBe(ok.id)
    })

    it('links a sub once, and refuses it to a second row live or hidden', async () => {
      const a = await adapter.identities.create(identity('link-a'))
      const b = await adapter.identities.create(identity('link-b'))
      const link = { addedAt: new Date('2026-01-02T03:04:05.000Z'), providerId: 'google', providerSub: 'g-1' }

      await adapter.identities.link(a.id, link)
      // A retried OAuth callback: the same pair again is a no-op, not a second entry.
      expect((await adapter.identities.link(a.id, { ...link, addedAt: new Date() }))?.providers).toEqual([link])
      await expect(adapter.identities.link(b.id, link)).rejects.toMatchObject({
        code: 'AUTH_PROVIDER_TAKEN',
        meta: { providerId: 'google' },
      })

      // `uq_auth_identity_providers_sub` is not partial, so hiding the holder does not release its login.
      await adapter.identities.softDelete(a.id, GRACE)
      await expect(adapter.identities.link(b.id, link)).rejects.toMatchObject({ code: 'AUTH_PROVIDER_TAKEN' })
    })

    it('unlinks every sub of one provider', async () => {
      const at = new Date()
      const created = await adapter.identities.create(
        identity('unlink', {
          providers: [
            { addedAt: at, providerId: 'google', providerSub: 'g-1' },
            { addedAt: at, providerId: 'password', providerSub: 'pw-1' },
          ],
        }),
      )

      const left = await adapter.identities.unlink(created.id, 'google')
      expect(left?.providers.map((p) => p.providerId)).toEqual(['password'])
      // Unlinking a provider the row does not hold leaves it as it was.
      expect((await adapter.identities.unlink(created.id, 'google'))?.providers).toHaveLength(1)
      expect(await adapter.identities.unlink(authUuidV7(), 'google')).toBeNull()
    })

    it('merges the dup into the survivor, and writes nothing when either side is missing', async () => {
      const at = new Date()
      const survivor = await adapter.identities.create(
        identity('survivor', { providers: [{ addedAt: at, providerId: 'password', providerSub: 'pw-s' }] }),
      )
      const dup = await adapter.identities.create(
        identity('dup', { providers: [{ addedAt: at, providerId: 'google', providerSub: 'g-dup' }] }),
      )
      await adapter.credentials.upsert(credential(dup.id), anywhere)
      await adapter.sessions.create(session('dup', { identityId: dup.id }))

      expect(await adapter.identities.merge(authUuidV7(), dup.id)).toBeNull()
      expect(await adapter.identities.merge(survivor.id, authUuidV7())).toBeNull()
      expect(await adapter.credentials.listByIdentity(dup.id, null, anywhere)).toHaveLength(1)

      const merged = await adapter.identities.merge(survivor.id, dup.id)
      expect(merged?.providers.map((p) => p.providerId).sort()).toEqual(['google', 'password'])
      expect(await adapter.credentials.listByIdentity(survivor.id, null, anywhere)).toHaveLength(1)
      expect((await adapter.sessions.getByHash(sid('dup')))?.identityId).toBe(survivor.id)
      expect(await adapter.identities.find({ id: dup.id })).toBeNull()
      // A dedupe job that hands in one id twice must not delete the account it means to keep.
      expect((await adapter.identities.merge(survivor.id, survivor.id))?.id).toBe(survivor.id)
    })
  })

  describe('credentials', () => {
    it('finds a live row before a revoked one, then the newest', async () => {
      // `created_at` defaults to the database's clock; a host clock a millisecond ahead of the container's
      // makes `chk_auth_credentials_revoked_after_created` refuse the insert, so the row names its own.
      await db
        .insert(authCredentials)
        .values({ ...credential(OWNER, { revokedAt: new Date(), secret: 'same' }), createdAt: ago(5000) })
      await db.insert(authCredentials).values({ ...credential(OWNER, { secret: 'same' }), createdAt: ago(3000) })
      const [newest] = await db
        .insert(authCredentials)
        .values({ ...credential(OWNER, { secret: 'same' }), createdAt: ago(2000) })
        .returning()

      expect((await adapter.credentials.findByHashedSecret('same', 'password', anywhere))?.id).toBe(newest?.id)
    })

    it('falls back to the revoked row when no live one answers', async () => {
      // Inserted rather than upserted, so the row names its own `created_at`: see the case above.
      const [revoked] = await db
        .insert(authCredentials)
        .values({ ...credential(OWNER, { revokedAt: new Date(), secret: 'only' }), createdAt: ago(5000) })
        .returning()

      expect((await adapter.credentials.findByHashedSecret('only', 'password', anywhere))?.id).toBe(revoked?.id)
    })

    it('matches a provider sub on oauth rows only, inside the tenant asked for', async () => {
      const metadata = { provider: 'google', sub: 's-1' }
      const oauth = await adapter.credentials.upsert(
        credential(OWNER, { kind: 'oauth', metadata, tenantId: 't-1' }),
        anywhere,
      )
      await adapter.credentials.upsert(credential(OWNER, { kind: 'api-key', metadata, tenantId: 't-1' }), anywhere)

      expect((await adapter.credentials.findByProviderSub('google', 's-1', { tenantId: 't-1' }))?.id).toBe(oauth.id)
      expect((await adapter.credentials.findByProviderSub('google', 's-1', anywhere))?.id).toBe(oauth.id)
      expect(await adapter.credentials.findByProviderSub('google', 's-1', { tenantId: 't-2' })).toBeNull()
      expect(await adapter.credentials.findByProviderSub('google', 'no-such-sub', anywhere)).toBeNull()
    })

    it('lists one identity, narrowed by kind and by tenant', async () => {
      await adapter.credentials.upsert(credential(OWNER, { tenantId: 't-1' }), anywhere)
      await adapter.credentials.upsert(credential(OWNER, { kind: 'totp', secret: 't' }), anywhere)

      expect(await adapter.credentials.listByIdentity(OWNER, null, anywhere)).toHaveLength(2)
      expect((await adapter.credentials.listByIdentity(OWNER, 'password', anywhere)).map((c) => c.kind)).toEqual([
        'password',
      ])
      // `eq` never matches NULL, so a global row sits outside a named tenant.
      expect(await adapter.credentials.listByIdentity(OWNER, null, { tenantId: 't-1' })).toHaveLength(1)
      expect(await adapter.credentials.listByIdentity(authUuidV7(), null, anywhere)).toEqual([])
    })

    it('rotates against a version, and revokes by id alone', async () => {
      const created = await adapter.credentials.upsert(credential(OWNER), anywhere)

      const rotated = await adapter.credentials.rotate(created.id, 'rotated', 1, anywhere)
      expect(rotated).toMatchObject({ secret: 'rotated', version: 2 })
      expect(rotated.lastUsedAt).toBeInstanceOf(Date)

      await expect(adapter.credentials.rotate(created.id, 'late', 1, anywhere)).rejects.toMatchObject({
        code: 'AUTH_STALE_WRITE',
      })
      // No version to lose, so a reach that matched nothing is a missing row.
      expect(await adapter.credentials.revoke(created.id, { tenantId: 'other' })).toBeNull()
      expect(await adapter.credentials.revoke(authUuidV7(), anywhere)).toBeNull()
      expect((await adapter.credentials.revoke(created.id, anywhere))?.revokedAt).toBeInstanceOf(Date)
    })

    it('merges a metadata patch into what the row already held', async () => {
      const created = await adapter.credentials.upsert(credential(OWNER, { metadata: { kept: 1 } }), anywhere)

      expect(await adapter.credentials.patchMetadata(created.id, { added: 2 }, anywhere)).toMatchObject({
        metadata: { added: 2, kept: 1 },
      })
      await expect(adapter.credentials.patchMetadata(authUuidV7(), { added: 2 }, anywhere)).rejects.toMatchObject({
        code: 'AUTH_CREDENTIAL_NOT_FOUND',
      })
    })

    it('deletes by id or by identity and kind, answering the rows as they were', async () => {
      const password = await adapter.credentials.upsert(credential(OWNER), anywhere)
      await adapter.credentials.upsert(credential(OWNER, { kind: 'totp', secret: 't' }), anywhere)

      expect((await adapter.credentials.deleteByKind(OWNER, 'totp', anywhere)).map((c) => c.kind)).toEqual(['totp'])
      expect(await adapter.credentials.delete(password.id, { tenantId: 'other' })).toBeNull()
      expect((await adapter.credentials.delete(password.id, anywhere))?.id).toBe(password.id)
    })
  })

  describe('sessions', () => {
    it('reads the row on an empty patch, and misses an unknown id either way', async () => {
      await adapter.sessions.create(session('read'))

      expect((await adapter.sessions.update(sid('read'), {})).id).toBe(sid('read'))
      expect((await adapter.sessions.update(sid('read'), { fresh: false })).fresh).toBe(false)
      for (const patch of [{}, { fresh: false }]) {
        await expect(adapter.sessions.update(sid('nope'), patch)).rejects.toMatchObject({
          code: 'AUTH_SESSION_REVOKED',
        })
      }
    })

    it('lists and deletes by identity inside a tenant, never reaching a global row', async () => {
      await adapter.sessions.create(session('global'))
      await adapter.sessions.create(session('tenant', { tenantId: 't-1' }))

      expect((await adapter.sessions.listByIdentity(OWNER, { tenantId: 't-1' })).map((s) => s.id)).toEqual([
        sid('tenant'),
      ])
      expect(await adapter.sessions.listByIdentity(OWNER, anywhere)).toHaveLength(2)
      await adapter.sessions.deleteAllForIdentity(OWNER, { tenantId: 't-1' })
      expect((await adapter.sessions.listByIdentity(OWNER, anywhere)).map((s) => s.id)).toEqual([sid('global')])
      await adapter.sessions.delete(sid('global'))
      expect(await adapter.sessions.listByIdentity(OWNER, anywhere)).toEqual([])
    })

    it('purges a session past the idle deadline, not one still inside it', async () => {
      await adapter.sessions.create(session('live'))
      // The idle deadline passed while the absolute ceiling is still ahead: reading only the ceiling
      // leaves it in the table for hours.
      await adapter.sessions.create(
        session('idle', {
          absoluteExpiresAt: ahead(60_000),
          createdAt: ago(120_000),
          expiresAt: ago(60_000),
          rotatedAt: ago(120_000),
        }),
      )

      expect(await adapter.sessions.gc(Date.now())).toEqual({ deleted: 1 })
      expect((await adapter.sessions.getByHash(sid('live')))?.id).toBe(sid('live'))
    })

    it('reads factors and actingAs written as garbage as empty', async () => {
      await adapter.sessions.create(session('garbage', { factors: [{ completedAt: new Date(), method: 'password' }] }))
      await pool.query(`UPDATE auth_sessions SET factors = '"nope"'::jsonb, acting_as = '[1]'::jsonb WHERE id = $1`, [
        sid('garbage'),
      ])

      expect(await adapter.sessions.getByHash(sid('garbage'))).toMatchObject({ actingAs: null, factors: [] })
    })
  })

  describe('every rule the schema enforces answers a typed error', () => {
    const violations: { code: AuthError.Code; constraint: string; run: () => Promise<unknown> }[] = [
      {
        code: 'AUTH_ALREADY_EXISTS',
        constraint: 'auth_identities_pkey',
        run: () => db.insert(authIdentities).values({ ...row('twin'), id: OWNER }),
      },
      {
        code: 'AUTH_EMAIL_TAKEN',
        constraint: 'uq_auth_identities_email',
        run: () =>
          adapter.identities.create(identity('x', { profile: { email: 'OWNER@adapter.test', username: 'x' } })),
      },
      {
        code: 'AUTH_USERNAME_TAKEN',
        constraint: 'uq_auth_identities_username',
        run: () =>
          adapter.identities.create(identity('x', { profile: { email: 'x@adapter.test', username: 'Owner' } })),
      },
      {
        code: 'AUTH_INVALID_PARAMETERS',
        constraint: 'chk_auth_identities_profile_shape',
        run: () =>
          db.insert(authIdentities).values({ ...row('shape'), profile: sql`'{"email":"s@adapter.test"}'::jsonb` }),
      },
      {
        code: 'AUTH_INVALID_PARAMETERS',
        constraint: 'chk_auth_identities_version',
        run: () => db.insert(authIdentities).values({ ...row('v0'), version: 0 }),
      },
      {
        code: 'AUTH_PROVIDER_TAKEN',
        constraint: 'uq_auth_identity_providers_sub',
        run: async () => {
          const link = { providerId: 'google', providerSub: 'g-dup' }
          await adapter.identities.create(identity('sub-a', { providers: [link] }))
          return adapter.identities.create(identity('sub-b', { providers: [link] }))
        },
      },
      {
        code: 'AUTH_PROVIDER_TAKEN',
        constraint: 'uq_auth_identity_providers_owned',
        run: async () => {
          const created = await adapter.identities.create(
            identity('owned', { providers: [{ providerId: 'google', providerSub: 'g-owned-1' }] }),
          )
          return db
            .insert(authIdentityProviders)
            .values({ identityId: created.id, providerId: 'google', providerSub: 'g-owned-2' })
        },
      },
      {
        code: 'AUTH_IDENTITY_NOT_FOUND',
        constraint: 'fk_auth_identity_providers_identity',
        run: () =>
          db
            .insert(authIdentityProviders)
            .values({ identityId: authUuidV7(), providerId: 'google', providerSub: 'g-orphan' }),
      },
      {
        code: 'AUTH_ALREADY_EXISTS',
        constraint: 'auth_identity_providers_pkey',
        run: async () => {
          const id = authUuidV7()
          return db.insert(authIdentityProviders).values([
            { id, identityId: OWNER, providerId: 'google', providerSub: 'g-pk-1' },
            { id, identityId: OWNER, providerId: 'github', providerSub: 'g-pk-2' },
          ])
        },
      },
      {
        code: 'AUTH_INVALID_PARAMETERS',
        constraint: 'chk_auth_identity_providers_sub_not_blank',
        run: () =>
          adapter.identities.create(identity('blank', { providers: [{ providerId: 'google', providerSub: '' }] })),
      },
      {
        code: 'AUTH_INVALID_PARAMETERS',
        constraint: 'chk_auth_identity_providers_provider_not_blank',
        run: () =>
          adapter.identities.create(identity('nameless', { providers: [{ providerId: '', providerSub: 's' }] })),
      },
      {
        code: 'AUTH_ALREADY_EXISTS',
        constraint: 'auth_credentials_pkey',
        run: async () => {
          const first = await adapter.credentials.upsert(credential(OWNER), anywhere)
          return db.insert(authCredentials).values({ ...credential(OWNER), id: first.id })
        },
      },
      {
        code: 'AUTH_IDENTITY_NOT_FOUND',
        constraint: 'fk_auth_credentials_identity',
        run: () => adapter.credentials.upsert(credential(authUuidV7()), anywhere),
      },
      {
        code: 'AUTH_INVALID_PARAMETERS',
        constraint: 'chk_auth_credentials_kind',
        run: () => db.insert(authCredentials).values({ ...credential(OWNER), kind: sql`'nope'` }),
      },
      {
        code: 'AUTH_INVALID_PARAMETERS',
        constraint: 'chk_auth_credentials_version',
        run: () => db.insert(authCredentials).values({ ...credential(OWNER), version: 0 }),
      },
      {
        code: 'AUTH_INVALID_PARAMETERS',
        constraint: 'chk_auth_credentials_secret_not_blank',
        run: () => adapter.credentials.upsert(credential(OWNER, { secret: '   ' }), anywhere),
      },
      {
        code: 'AUTH_INVALID_PARAMETERS',
        constraint: 'chk_auth_credentials_tenant_not_blank',
        run: () => adapter.credentials.upsert(credential(OWNER, { tenantId: '' }), anywhere),
      },
      {
        code: 'AUTH_INVALID_PARAMETERS',
        constraint: 'chk_auth_credentials_expires_after_created',
        run: () => adapter.credentials.upsert(credential(OWNER, { expiresAt: ago(60_000) }), anywhere),
      },
      {
        code: 'AUTH_INVALID_PARAMETERS',
        constraint: 'chk_auth_credentials_revoked_after_created',
        run: () => adapter.credentials.upsert(credential(OWNER, { revokedAt: ago(60_000) }), anywhere),
      },
      {
        code: 'AUTH_INVALID_PARAMETERS',
        constraint: 'chk_auth_credentials_last_used_after_created',
        run: () => adapter.credentials.upsert(credential(OWNER, { lastUsedAt: ago(60_000) }), anywhere),
      },
      {
        code: 'AUTH_ALREADY_EXISTS',
        constraint: 'auth_sessions_pkey',
        run: async () => {
          await adapter.sessions.create(session('twice'))
          return adapter.sessions.create(session('twice'))
        },
      },
      {
        code: 'AUTH_IDENTITY_NOT_FOUND',
        constraint: 'fk_auth_sessions_identity',
        run: () => adapter.sessions.create(session('orphan', { identityId: authUuidV7() })),
      },
      {
        code: 'AUTH_INVALID_PARAMETERS',
        constraint: 'chk_auth_sessions_kind',
        run: () => db.insert(authSessions).values({ ...session('kind'), kind: sql`'browser'` }),
      },
      {
        code: 'AUTH_INVALID_PARAMETERS',
        constraint: 'chk_auth_sessions_aal',
        run: () => db.insert(authSessions).values({ ...session('aal'), aal: sql`9` }),
      },
      {
        code: 'AUTH_INVALID_PARAMETERS',
        constraint: 'chk_auth_sessions_id_length',
        run: () => adapter.sessions.create(session('short', { id: 'short' })),
      },
      {
        code: 'AUTH_INVALID_PARAMETERS',
        constraint: 'chk_auth_sessions_tenant_not_blank',
        run: () => adapter.sessions.create(session('untenanted', { tenantId: '' })),
      },
      {
        code: 'AUTH_INVALID_PARAMETERS',
        constraint: 'chk_auth_sessions_expires_after_created',
        run: () => adapter.sessions.create(session('backdated', { expiresAt: ago(60_000) })),
      },
      {
        code: 'AUTH_INVALID_PARAMETERS',
        constraint: 'chk_auth_sessions_absolute_expires_after_expires',
        run: () => adapter.sessions.create(session('capped', { absoluteExpiresAt: ahead(1000) })),
      },
      {
        code: 'AUTH_INVALID_PARAMETERS',
        constraint: 'chk_auth_sessions_rotated_after_created',
        run: () => adapter.sessions.create(session('rotated', { rotatedAt: ago(60_000) })),
      },
    ]

    it.each(violations)('$constraint answers $code', async ({ code, constraint, run }) => {
      const { error } = await attempt(run)

      expect(error?.code).toBe(code)
      // The driver error is kept on `cause`, so a log can still name the rule.
      expect(constraintOf(error)).toBe(constraint)
    })

    it('leaves no constraint the schema declares untested', () => {
      const declared = [authIdentities, authIdentityProviders, authCredentials, authSessions].flatMap((table) => {
        const { checks, columns, foreignKeys, indexes, name } = getTableConfig(table)
        return [
          ...(columns.some((column) => column.primary) ? [`${name}_pkey`] : []),
          ...checks.map((check) => check.name),
          ...foreignKeys.map((fk) => fk.getName()),
          ...indexes.flatMap((index) => (index.config.unique && index.config.name ? [index.config.name] : [])),
        ]
      })

      expect(violations.map((v) => v.constraint).sort()).toEqual(declared.sort())
    })

    it('answers a value postgres cannot read, and a required one left out', async () => {
      const cast = await attempt(() => adapter.sessions.create(session('cast', { identityId: 'not-a-uuid' })))
      expect(cast.error?.code).toBe('AUTH_INVALID_PARAMETERS')

      const missing = await attempt(() =>
        db.insert(authCredentials).values({ ...credential(OWNER), secret: sql`null` }),
      )
      expect(missing.error?.code).toBe('AUTH_NOT_ENOUGH_PARAMETERS')
    })

    it('answers a statement the server gave up on as unavailable', async () => {
      const { error } = await attempt(() =>
        db.transaction(async (tx) => {
          await tx.execute(sql`set local statement_timeout = 1`)
          await tx.execute(sql`select pg_sleep(1)`)
        }),
      )

      expect(error?.code).toBe('AUTH_ADAPTER_UNAVAILABLE')
    })

    it('answers a database without the auth schema as misconfigured', async () => {
      const empty = new Pool({ connectionString: await isolatedDatabaseUrl('pg_adapter_empty') })
      try {
        const { error } = await new DrizzlePgAdapter(drizzle(empty)).identities.find({ id: OWNER }).wrap()

        expect(error?.code).toBe('AUTH_MISCONFIGURED')
        // The table name is internal; nothing about it reaches a caller's logs.
        expect(JSON.stringify(error)).not.toContain('auth_identities')
      } finally {
        await empty.end()
      }
    })

    it('answers a server it cannot reach as unavailable', async () => {
      const unreachable = new Pool({ connectionString: 'postgres://nobody:nothing@127.0.0.1:1/none' })
      try {
        const { error } = await new DrizzlePgAdapter(drizzle(unreachable)).identities.find({ id: OWNER }).wrap()

        expect(error?.code).toBe('AUTH_ADAPTER_UNAVAILABLE')
      } finally {
        await unreachable.end()
      }
    })
  })
})
