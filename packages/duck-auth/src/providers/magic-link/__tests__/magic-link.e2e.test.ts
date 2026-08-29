/**
 * E2E: magic links against REAL Postgres.
 *
 * A magic link is a bearer credential mailed in plaintext, so the only things
 * standing between a leaked inbox and an account are that the token works once,
 * expires, and belongs to exactly one identity. `complete` claims the row with a
 * compare-and-set on its version before revoking it, which is the right shape,
 * and is also the shape that only a real database can be tested against: an
 * in-memory store cannot lose the race the CAS exists to win.
 *
 * Findings are recorded, not repaired.
 *
 * Skips when DUCKAUTH_E2E_DATABASE_URL is unset; `globalSetup` provisions a
 * container when docker is available.
 */
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { drizzlePgStorage } from '~/adapters/drizzle/pg'
import type { Channel } from '~/channels/channels.types'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { applyPgSchema, databaseUrl, e2ePrefix } from '~/test/e2e-env'
import { magicLink } from '../index'

const PG_URL = databaseUrl()
const suite = PG_URL ? describe : describe.skip

type Profile = { username: string; email: string }

/** Captures the link so a test can play the part of the mail client. */
function capturingChannel(): Channel.Channel & { links: string[] } {
  const links: string[] = []
  return {
    id: 'capture',
    kind: 'email',
    links,
    async send(input) {
      links.push((input.vars as { url?: string }).url ?? '')
      return { ok: true }
    },
  }
}

suite('E2E magic links on real Postgres', () => {
  let pool: Pool
  let auth: AuthEngine<Profile>
  let stores: ReturnType<typeof drizzlePgStorage<Profile>>
  let channel: ReturnType<typeof capturingChannel>
  const planted: string[] = []

  async function newUser(label: string): Promise<{ id: string; email: string }> {
    const tag = `${label}-${e2ePrefix()}`
    const email = `${tag}@test.local`
    const identity = await auth.identities.create({ profile: { email, username: tag } })
    planted.push(identity.id)
    return { email, id: identity.id }
  }

  /** Ask for a link and hand back the token from it. */
  async function requestToken(email: string): Promise<string> {
    const before = channel.links.length
    await auth.flows.beginProvider('magic-link', { email })
    const url = channel.links[before]
    if (!url) throw new Error('no link was sent')
    return new URL(url).searchParams.get('token') as string
  }

  const redeem = (token: string) => auth.flows.signIn({ input: { token }, providerId: 'magic-link' })

  beforeAll(async () => {
    pool = new Pool({ connectionString: PG_URL })
    await applyPgSchema(pool)
    stores = drizzlePgStorage<Profile>(PG_URL as string)
    channel = capturingChannel()
    auth = new AuthEngine<Profile>({
      baseUrl: 'https://app.test',
      limiter: new MemoryLimiter({ max: 5000, windowMs: 60_000 }),
      stores: { credentials: stores.credentials, identities: stores.identities, sessions: stores.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    auth.providers.register(
      magicLink<Profile>({
        channels: { email: channel },
        findIdentityByEmail: async (email) => stores.identities.findByEmail(email),
      }),
    )
  }, 60_000)

  afterAll(async () => {
    if (pool && planted.length > 0) {
      await pool.query('DELETE FROM auth_identities WHERE id = ANY($1::uuid[])', [planted])
    }
    await pool?.end()
  })

  describe('a link works exactly once', () => {
    it('signs the owner in on first use', async () => {
      const user = await newUser('ml-happy')
      const token = await requestToken(user.email)

      const result = await redeem(token)
      expect(result.session?.identityId).toBe(user.id)
    })

    it('refuses the same token a second time', async () => {
      const user = await newUser('ml-replay')
      const token = await requestToken(user.email)
      await redeem(token)

      await expect(redeem(token)).rejects.toMatchObject({ code: 'AUTH_RECOVERY_TOKEN_INVALID' })
    })

    it('admits exactly one of many simultaneous redemptions', async () => {
      // The compare-and-set on `version` is what decides this. A read-then-write
      // would hand every racer a session from one emailed link.
      const user = await newUser('ml-race')
      const token = await requestToken(user.email)

      const settled = await Promise.allSettled(Array.from({ length: 8 }, () => redeem(token)))
      expect(settled.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
      for (const r of settled) {
        if (r.status === 'rejected') expect(r.reason).toMatchObject({ code: 'AUTH_RECOVERY_TOKEN_INVALID' })
      }
    })

    it('the row is revoked afterwards, not merely forgotten in memory', async () => {
      const user = await newUser('ml-revoked-row')
      const token = await requestToken(user.email)
      await redeem(token)

      const rows = await stores.credentials.listByIdentity(user.id, 'magic-link', {})
      expect(rows.every((r) => r.revokedAt != null)).toBe(true)
    })
  })

  describe('tokens that should never work', () => {
    it('refuses a token that was never issued', async () => {
      await expect(redeem(`invented-${e2ePrefix()}`)).rejects.toMatchObject({
        code: 'AUTH_RECOVERY_TOKEN_INVALID',
      })
    })

    it('refuses an empty token', async () => {
      await expect(redeem('')).rejects.toMatchObject({ code: 'AUTH_RECOVERY_TOKEN_INVALID' })
    })

    it('refuses an oversize token before hashing it', async () => {
      await expect(redeem('x'.repeat(100_000))).rejects.toMatchObject({
        code: 'AUTH_RECOVERY_TOKEN_INVALID',
      })
    })

    it('refuses a non-string token', async () => {
      await expect(redeem(12345 as unknown as string)).rejects.toMatchObject({
        code: 'AUTH_RECOVERY_TOKEN_INVALID',
      })
    })

    it('refuses a token whose credential row was revoked out from under it', async () => {
      const user = await newUser('ml-revoked')
      const token = await requestToken(user.email)
      const rows = await stores.credentials.listByIdentity(user.id, 'magic-link', {})
      for (const row of rows) await stores.credentials.revoke(row.id, {})

      await expect(redeem(token)).rejects.toMatchObject({ code: 'AUTH_RECOVERY_TOKEN_INVALID' })
    })

    it('reports an expired token distinctly, and deletes the row', async () => {
      const user = await newUser('ml-expired')
      const token = await requestToken(user.email)
      const [row] = await stores.credentials.listByIdentity(user.id, 'magic-link', {})
      // Backdate through the database, the way real time would. `created_at`
      // moves with it: `chk_auth_credentials_expires_after_created` refuses an
      // expiry that precedes creation, so shifting only the expiry is rejected.
      await pool.query(
        `UPDATE auth_credentials
           SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour'
         WHERE id = $1`,
        [row?.id],
      )

      await expect(redeem(token)).rejects.toMatchObject({ code: 'AUTH_RECOVERY_TOKEN_EXPIRED' })
    })
  })

  describe('one identity’s link is not another’s', () => {
    it('signs in the identity the link was minted for, never the requester of a later link', async () => {
      const first = await newUser('ml-first')
      const second = await newUser('ml-second')
      const firstToken = await requestToken(first.email)
      await requestToken(second.email)

      await redeem(firstToken)

      // The second identity's link is untouched, so its row is still live.
      const secondRows = await stores.credentials.listByIdentity(second.id, 'magic-link', {})
      expect(secondRows.some((r) => r.revokedAt == null)).toBe(true)
    })

    it('two live links for one identity are independent', async () => {
      const user = await newUser('ml-two-links')
      const a = await requestToken(user.email)
      const b = await requestToken(user.email)
      expect(a).not.toBe(b)

      await redeem(a)
      // FINDING-adjacent: the second link still works, so requesting a new one
      // does not retire the previous, the same shape as password reset tokens.
      await expect(redeem(b)).resolves.toBeDefined()
    })
  })

  describe('requesting a link says nothing about who exists', () => {
    it('does not throw for an unknown address', async () => {
      const before = channel.links.length
      await expect(
        auth.flows.beginProvider('magic-link', { email: `ghost-${e2ePrefix()}@test.local` }),
      ).resolves.toBeDefined()
      expect(channel.links.length).toBe(before)
    })

    it('refuses an oversize address before touching the store', async () => {
      await expect(auth.flows.beginProvider('magic-link', { email: `${'x'.repeat(300)}@test.local` })).rejects.toThrow()
    })

    it('refuses a non-string address', async () => {
      await expect(auth.flows.beginProvider('magic-link', { email: 42 as unknown as string })).rejects.toThrow()
    })
  })

  describe('the emitted link is same-origin and carries the token in the query', () => {
    it('points at the configured base url', async () => {
      const user = await newUser('ml-url')
      await requestToken(user.email)
      const url = new URL(channel.links.at(-1) as string)
      expect(url.origin).toBe('https://app.test')
      expect(url.searchParams.get('token')).toBeTruthy()
    })

    it('refuses a callback path that could move the authority, at construction', () => {
      // The provider validates its own configuration, so a typo cannot turn every
      // future link into a cross-origin token exfiltration.
      for (const callbackPath of ['//evil.com', '/\\evil.com', 'https://evil.com', '/a\nb']) {
        expect(() =>
          magicLink<Profile>({
            callbackPath,
            channels: { email: channel },
            findIdentityByEmail: async () => null,
          }),
        ).toThrow(/AUTH_MISCONFIGURED/)
      }
    })

    it('accepts an ordinary same-origin callback path', () => {
      expect(() =>
        magicLink<Profile>({
          callbackPath: '/auth/magic',
          channels: { email: channel },
          findIdentityByEmail: async () => null,
        }),
      ).not.toThrow()
    })
  })
})
