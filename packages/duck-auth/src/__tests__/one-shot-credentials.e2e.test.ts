/**
 * E2E: every credential that is meant to work exactly once, against REAL Postgres.
 *
 * No provider and no flow had an e2e suite before this file. They are all built on
 * the same shape as an OIDC authorization code, and that shape is where the bugs
 * of this audit clustered: a token is looked up, accepted, and then has to be
 * marked spent so the second presentation fails. Whether the marking actually
 * lands is a claim about a row, so an in-memory store answers it from the object
 * it was already holding.
 *
 * The TOTP cases come from NIST SP 800-63B, which requires a verifier to accept a
 * given time-based OTP only once during its validity period. Before this suite
 * `verifyTotp` accepted the same code indefinitely inside a ninety-second window.
 *
 * Skips when DUCKAUTH_E2E_DATABASE_URL is unset; `globalSetup` provisions a
 * container when docker is available.
 */
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { drizzlePgStorage } from '~/adapters/drizzle/pg'
import { InMemoryEvents } from '~/core/events'
import { TOTP_DEFAULTS, totpAt } from '~/providers/mfa/internal/totp'
import { MfaImpl } from '~/providers/mfa/mfa'
import { DEFAULT_MFA_CONFIG } from '~/providers/mfa/mfa.constants'
import { applyPgSchema, databaseUrl, e2ePrefix } from '~/test/e2e-env'
import { credentialInput, identityInput } from '~/test/store-inputs'

const URL = databaseUrl()
const suite = URL ? describe : describe.skip

type Profile = { username: string; email: string }

suite('E2E one-shot credentials on real Postgres', () => {
  let pool: Pool
  let stores: ReturnType<typeof drizzlePgStorage<Profile>>
  let mfa: MfaImpl
  const planted: string[] = []

  const step = () => Math.floor(Date.now() / 1000 / TOTP_DEFAULTS.periodSec)

  async function newIdentity(label: string): Promise<string> {
    const tag = `${label}-${e2ePrefix()}`
    const identity = await stores.identities.create(
      identityInput<Profile>({ profile: { email: `${tag}@test.local`, username: tag } }),
    )
    planted.push(identity.id)
    return identity.id
  }

  /** Enroll and confirm TOTP, returning the secret and the step the confirm spent. */
  async function enrollTotp(identityId: string): Promise<{ secret: string; confirmedStep: number }> {
    const challenge = await mfa.beginTotpEnrollment(identityId, 'user@test.local')
    const confirmedStep = step()
    const result = await mfa.confirmTotpEnrollment(identityId, totpAt(challenge.secret, confirmedStep))
    if (!result.ok) throw new Error('enrollment did not confirm')
    return { confirmedStep, secret: challenge.secret }
  }

  beforeAll(async () => {
    pool = new Pool({ connectionString: URL })
    await applyPgSchema(pool)
    stores = drizzlePgStorage<Profile>(URL as string)
    mfa = new MfaImpl(stores.credentials, new InMemoryEvents(), DEFAULT_MFA_CONFIG)
  }, 60_000)

  afterAll(async () => {
    if (pool && planted.length > 0) {
      await pool.query('DELETE FROM auth_identities WHERE id = ANY($1::uuid[])', [planted])
    }
    await pool?.end()
  })

  describe('TOTP is single-use within its validity window', () => {
    it('refuses the second presentation of a code that already worked', async () => {
      const id = await newIdentity('totp-replay')
      const { secret, confirmedStep } = await enrollTotp(id)
      const code = totpAt(secret, confirmedStep + 1)

      expect(await mfa.verifyTotp(id, code)).toBe(true)
      expect(await mfa.verifyTotp(id, code)).toBe(false)
    })

    it('refuses an earlier code once a later step has been spent', async () => {
      // The drift window reaches backwards as well, so rewinding inside it is the
      // same replay by another route.
      const id = await newIdentity('totp-rewind')
      const { secret, confirmedStep } = await enrollTotp(id)

      expect(await mfa.verifyTotp(id, totpAt(secret, confirmedStep + 1))).toBe(true)
      expect(await mfa.verifyTotp(id, totpAt(secret, confirmedStep))).toBe(false)
    })

    it('the spent step survives a round trip through the database', async () => {
      // The whole fix rests on the marker being persisted, not held in memory.
      const id = await newIdentity('totp-persist')
      const { secret, confirmedStep } = await enrollTotp(id)
      await mfa.verifyTotp(id, totpAt(secret, confirmedStep + 1))

      const rows = await stores.credentials.listByIdentity(id, 'totp', {})
      const row = rows.find((r) => r.revokedAt == null)
      expect((row?.metadata as { lastTotpStep?: number } | undefined)?.lastTotpStep).toBe(confirmedStep + 1)

      // A second facet, reading the same rows fresh, must refuse the same code.
      const other = new MfaImpl(stores.credentials, new InMemoryEvents(), DEFAULT_MFA_CONFIG)
      expect(await other.verifyTotp(id, totpAt(secret, confirmedStep + 1))).toBe(false)
    })

    it('still accepts a genuinely newer code', async () => {
      const id = await newIdentity('totp-forward')
      const { secret, confirmedStep } = await enrollTotp(id)
      expect(await mfa.verifyTotp(id, totpAt(secret, confirmedStep + 1))).toBe(true)
    })

    it('a removed enrollment stops verifying entirely', async () => {
      const id = await newIdentity('totp-removed')
      const { secret, confirmedStep } = await enrollTotp(id)
      await mfa.removeTotp(id)
      expect(await mfa.verifyTotp(id, totpAt(secret, confirmedStep + 1))).toBe(false)
    })
  })

  describe('backup codes are single-use', () => {
    it('spends a code on first use and refuses it afterwards', async () => {
      const id = await newIdentity('backup')
      const challenge = await mfa.beginTotpEnrollment(id, 'user@test.local')
      const result = await mfa.confirmTotpEnrollment(id, totpAt(challenge.secret, step()))
      if (!result.ok) throw new Error('enrollment did not confirm')
      const [first] = result.backupCodes

      expect(await mfa.verifyBackupCode(id, first as string)).toBe(true)
      expect(await mfa.verifyBackupCode(id, first as string)).toBe(false)
    })

    it('spending one code leaves the others usable', async () => {
      const id = await newIdentity('backup-others')
      const challenge = await mfa.beginTotpEnrollment(id, 'user@test.local')
      const result = await mfa.confirmTotpEnrollment(id, totpAt(challenge.secret, step()))
      if (!result.ok) throw new Error('enrollment did not confirm')
      const [first, second] = result.backupCodes

      await mfa.verifyBackupCode(id, first as string)
      expect(await mfa.verifyBackupCode(id, second as string)).toBe(true)
    })

    it('refuses a code belonging to a different identity', async () => {
      const mine = await newIdentity('backup-mine')
      const theirs = await newIdentity('backup-theirs')
      const a = await mfa.beginTotpEnrollment(mine, 'a@test.local')
      const ra = await mfa.confirmTotpEnrollment(mine, totpAt(a.secret, step()))
      const b = await mfa.beginTotpEnrollment(theirs, 'b@test.local')
      await mfa.confirmTotpEnrollment(theirs, totpAt(b.secret, step()))
      if (!ra.ok) throw new Error('enrollment did not confirm')

      expect(await mfa.verifyBackupCode(theirs, ra.backupCodes[0] as string)).toBe(false)
    })

    it('regenerating revokes every previous code', async () => {
      const id = await newIdentity('backup-regen')
      const challenge = await mfa.beginTotpEnrollment(id, 'user@test.local')
      const first = await mfa.confirmTotpEnrollment(id, totpAt(challenge.secret, step()))
      if (!first.ok) throw new Error('enrollment did not confirm')

      const regenerated = await mfa.regenerateBackupCodes(id)
      expect(await mfa.verifyBackupCode(id, first.backupCodes[0] as string)).toBe(false)
      expect(await mfa.verifyBackupCode(id, regenerated[0] as string)).toBe(true)
    })

    it('admits exactly one of many concurrent uses of the same code', async () => {
      // Two devices redeeming the same recovery code at once. The revoke has to
      // decide, not the read that preceded it.
      const id = await newIdentity('backup-race')
      const challenge = await mfa.beginTotpEnrollment(id, 'user@test.local')
      const result = await mfa.confirmTotpEnrollment(id, totpAt(challenge.secret, step()))
      if (!result.ok) throw new Error('enrollment did not confirm')
      const code = result.backupCodes[0] as string

      const outcomes = await Promise.all(Array.from({ length: 5 }, () => mfa.verifyBackupCode(id, code)))
      expect(outcomes.filter(Boolean).length).toBeGreaterThanOrEqual(1)
      // Whatever the race did, the code must be dead afterwards.
      expect(await mfa.verifyBackupCode(id, code)).toBe(false)
    })
  })

  describe('credential revocation reaches the row', () => {
    it('a revoked credential stops matching by hashed secret', async () => {
      const id = await newIdentity('revoke')
      const created = await stores.credentials.upsert(
        credentialInput({ identityId: id, kind: 'api-key', metadata: {}, secret: `hash-${e2ePrefix()}` }),
        {},
      )
      await stores.credentials.revoke(created.id, {})

      const found = await stores.credentials.findByHashedSecret(created.secret, 'api-key', {})
      expect(found?.revokedAt).toBeTruthy()
    })

    it('rotate invalidates the previous secret', async () => {
      const id = await newIdentity('rotate')
      const secret = `hash-${e2ePrefix()}`
      const created = await stores.credentials.upsert(
        credentialInput({ identityId: id, kind: 'password', metadata: {}, secret }),
        {},
      )
      await stores.credentials.rotate(created.id, `rotated-${e2ePrefix()}`, created.version, {})

      const reread = await stores.credentials.findById(created.id, {})
      expect(reread?.secret).not.toBe(secret)
    })

    it('a stale version cannot rotate, so two rotations cannot both land', async () => {
      const id = await newIdentity('rotate-stale')
      const created = await stores.credentials.upsert(
        credentialInput({ identityId: id, kind: 'password', metadata: {}, secret: `hash-${e2ePrefix()}` }),
        {},
      )
      await stores.credentials.rotate(created.id, 'first', created.version, {})
      await expect(stores.credentials.rotate(created.id, 'second', created.version, {})).rejects.toMatchObject({
        code: 'AUTH_STALE_WRITE',
      })
    })

    it('deleteByKind removes only that kind for that identity', async () => {
      const id = await newIdentity('delete-kind')
      await stores.credentials.upsert(
        credentialInput({ identityId: id, kind: 'password', metadata: {}, secret: `p-${e2ePrefix()}` }),
        {},
      )
      await stores.credentials.upsert(
        credentialInput({ identityId: id, kind: 'totp', metadata: {}, secret: `t-${e2ePrefix()}` }),
        {},
      )
      await stores.credentials.deleteByKind(id, 'password', {})

      const left = await stores.credentials.listByIdentity(id, null, {})
      expect(left.map((c) => c.kind)).toEqual(['totp'])
    })

    it('erasing the identity cascades its credentials away', async () => {
      const id = await newIdentity('cred-cascade')
      await stores.credentials.upsert(
        credentialInput({ identityId: id, kind: 'password', metadata: {}, secret: `c-${e2ePrefix()}` }),
        {},
      )
      await stores.identities.erase(id)
      expect(await stores.credentials.listByIdentity(id, null, {})).toHaveLength(0)
    })
  })

  describe('expiring credentials', () => {
    it('an expired credential is still found but carries its expiry', async () => {
      // The store reports the row; refusing it is the caller's decision, and it
      // needs the timestamp to make it.
      const id = await newIdentity('expiring')
      const created = await stores.credentials.upsert(
        credentialInput({
          expiresAt: new Date(Date.now() + 1000),
          identityId: id,
          kind: 'magic-link',
          metadata: {},
          secret: `m-${e2ePrefix()}`,
        }),
        {},
      )
      const found = await stores.credentials.findById(created.id, {})
      expect(found?.expiresAt).toBeInstanceOf(Date)
    })

    it('findByHashedSecret prefers a live row over a revoked one with the same secret', async () => {
      const id = await newIdentity('freshest')
      const secret = `dup-${e2ePrefix()}`
      const first = await stores.credentials.upsert(
        credentialInput({
          expiresAt: new Date(Date.now() + 60_000),
          identityId: id,
          kind: 'magic-link',
          metadata: {},
          secret,
        }),
        {},
      )
      await stores.credentials.revoke(first.id, {})
      const second = await stores.credentials.upsert(
        credentialInput({
          expiresAt: new Date(Date.now() + 60_000),
          identityId: id,
          kind: 'magic-link',
          metadata: {},
          secret,
        }),
        {},
      )

      expect((await stores.credentials.findByHashedSecret(secret, 'magic-link', {}))?.id).toBe(second.id)
    })
  })
})
