import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthMemoryAdapter } from '../../../adapters/memory'
import { AuthEngine } from '../../../core/engine'
import { AuthCookieTransport } from '../../../core/transport/cookie'
import type { AuthChannel } from '../../../core/types/channel'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { authMagicLink } from '../index'

interface MyProfile {
  email: string
}

function fakeChannel(): AuthChannel.IChannel & { sent: Array<{ to: string; url: string }> } {
  const sent: Array<{ to: string; url: string }> = []
  return {
    kind: 'email',
    id: 'fake',
    sent,
    async send(input) {
      const url = (input.vars as { url?: string }).url ?? ''
      const email = (input.identity.profile as { email?: string } | undefined)?.email ?? ''
      sent.push({ to: email, url })
      return { ok: true }
    },
  }
}

function buildAuth(opts: { autoCreate?: boolean; channel?: AuthChannel.IChannel } = {}): {
  auth: AuthEngine<MyProfile>
  adapter: AuthMemoryAdapter<MyProfile>
  channel: AuthChannel.IChannel & { sent: Array<{ to: string; url: string }> }
} {
  const adapter = new AuthMemoryAdapter<MyProfile>()
  const channel = (opts.channel as AuthChannel.IChannel & { sent: Array<{ to: string; url: string }> }) ?? fakeChannel()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.example.com',
    transport: new AuthCookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new AuthMemoryLimiter({ max: 3, windowMs: 60_000 }),
  })
  auth.providers.register(
    authMagicLink<MyProfile>({
      channels: { email: channel },
      findIdentityByEmail: (email) => adapter.identities.findByEmail(email, {}),
      autoCreateIdentity: opts.autoCreate ?? false,
      ttlMs: 1_000,
    }),
  )
  return { auth, adapter, channel }
}

function extractToken(url: string): string {
  const u = new URL(url)
  return u.searchParams.get('token') ?? ''
}

describe('magic-link provider', () => {
  describe('begin', () => {
    it('happy path: rate-limit consumed, channel.send called, token persisted (hashed)', async () => {
      const { auth, channel, adapter } = buildAuth()
      const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
      await auth.flows.beginProvider('magic-link', { email: 'a@x.com' })
      expect(channel.sent).toHaveLength(1)
      expect(channel.sent[0]?.to).toBe('a@x.com')
      const creds = await adapter.credentials.listByIdentity(identity.id, 'magic-link', {})
      expect(creds).toHaveLength(1)
      // Persisted secret is sha-256 hex; the plaintext token is in the link only.
      expect(creds[0]?.secret).toMatch(/^[0-9a-f]{64}$/)
      expect(creds[0]?.secret).not.toBe(extractToken(channel.sent[0]?.url ?? ''))
    })

    it('unknown email + autoCreate=false -> generic {ok:true} (no enumeration)', async () => {
      const { auth, channel, adapter } = buildAuth({ autoCreate: false })
      const intents = await auth.flows.beginProvider('magic-link', { email: 'ghost@x.com' })
      expect(intents).toEqual([{ type: 'json', status: 200, body: { ok: true } }])
      expect(channel.sent).toHaveLength(0)
      expect(await adapter.identities.findByEmail('ghost@x.com', {})).toBeNull()
    })

    it('unknown email + autoCreate=true -> identity created, token sent', async () => {
      const { auth, channel, adapter } = buildAuth({ autoCreate: true })
      await auth.flows.beginProvider('magic-link', { email: 'new@x.com' })
      expect(channel.sent).toHaveLength(1)
      const i = await adapter.identities.findByEmail('new@x.com', {})
      expect(i).not.toBeNull()
      expect(i?.providers.some((p) => p.providerId === 'magic-link')).toBe(true)
    })

    it('rate-limit trips after configured attempts', async () => {
      const { auth } = buildAuth({ autoCreate: true })
      for (let i = 0; i < 3; i++) {
        await auth.flows.beginProvider('magic-link', { email: 'x@x.com' }).catch(() => {})
      }
      await expect(auth.flows.beginProvider('magic-link', { email: 'x@x.com' })).rejects.toMatchObject({
        code: 'AUTH/RATE_LIMITED',
      })
    })

    it('channel send failure does NOT surface to the caller; emits signin.failed for operator visibility', async () => {
      const broken: AuthChannel.IChannel = {
        kind: 'email',
        id: 'broken',
        async send() {
          return { ok: false, error: 'smtp down' }
        },
      }
      const { auth } = buildAuth({ channel: broken })
      const seen: string[] = []
      auth.events.on('signin.failed', (payload) => {
        seen.push(payload.reason)
      })
      await auth.identities.create({ profile: { email: 'a@x.com' } })
      // Request returns ok:true (matches the no-identity-exists branch
      // - no enumeration via response code).
      const intents = await auth.flows.beginProvider('magic-link', { email: 'a@x.com' })
      expect(intents).toEqual([{ type: 'json', status: 200, body: { ok: true } }])
      // The failure surfaces on the events bus so operators can detect
      // channel outages without the requester learning anything.
      // `signin.failed` is emitted asynchronously by the fire-and-forget
      // path; yield to the microtask queue so the assertion sees it.
      await new Promise((r) => setImmediate(r))
      expect(seen).toEqual(['channel.send rejected delivery'])
    })

    it('missing channel surfaces AUTH/MISCONFIGURED', async () => {
      const { auth } = buildAuth()
      await auth.identities.create({ profile: { email: 'a@x.com' } })
      await expect(auth.flows.beginProvider('magic-link', { email: 'a@x.com', channel: 'sms' })).rejects.toMatchObject({
        code: 'AUTH/MISCONFIGURED',
      })
    })
  })

  describe('callbackPath open-redirect defense', () => {
    it('throws AUTH/MISCONFIGURED at construction when callbackPath is protocol-relative `//evil.com`', () => {
      expect(() =>
        authMagicLink<MyProfile>({
          channels: { email: fakeChannel() },
          findIdentityByEmail: async () => null,
          callbackPath: '//evil.com',
        }),
      ).toThrow(/MISCONFIGURED/)
    })

    it('throws on `/\\evil.com` (Windows-style escape)', () => {
      expect(() =>
        authMagicLink<MyProfile>({
          channels: { email: fakeChannel() },
          findIdentityByEmail: async () => null,
          callbackPath: '/\\evil.com',
        }),
      ).toThrow(/MISCONFIGURED/)
    })

    it('throws when callbackPath does not start with `/`', () => {
      expect(() =>
        authMagicLink<MyProfile>({
          channels: { email: fakeChannel() },
          findIdentityByEmail: async () => null,
          callbackPath: 'https://evil.com',
        }),
      ).toThrow(/MISCONFIGURED/)
    })

    it('accepts a safe same-origin callback path', () => {
      expect(() =>
        authMagicLink<MyProfile>({
          channels: { email: fakeChannel() },
          findIdentityByEmail: async () => null,
          callbackPath: '/login/finish',
        }),
      ).not.toThrow()
    })
  })

  describe('complete (full e2e sign-in via flows)', () => {
    it('valid token issues a session via auth.flows.signIn', async () => {
      const { auth, channel } = buildAuth({ autoCreate: true })
      await auth.flows.beginProvider('magic-link', { email: 'a@x.com' })
      const token = extractToken(channel.sent[0]?.url ?? '')

      const signinHandler = vi.fn()
      auth.events.on('signin.success', signinHandler)
      const result = await auth.flows.signIn({ providerId: 'magic-link', input: { token } })
      expect(result.session!.factors[0]?.method).toBe('magic-link')
      expect(signinHandler).toHaveBeenCalledOnce()
    })

    it('replay of same token surfaces AUTH/RECOVERY_TOKEN_INVALID (single-use)', async () => {
      const { auth, channel } = buildAuth({ autoCreate: true })
      await auth.flows.beginProvider('magic-link', { email: 'a@x.com' })
      const token = extractToken(channel.sent[0]?.url ?? '')
      await auth.flows.signIn({ providerId: 'magic-link', input: { token } })
      await expect(auth.flows.signIn({ providerId: 'magic-link', input: { token } })).rejects.toMatchObject({
        code: 'AUTH/RECOVERY_TOKEN_INVALID',
      })
    })

    it('concurrent completes with the same token - exactly one succeeds (TOCTOU defense)', async () => {
      const { auth, channel } = buildAuth({ autoCreate: true })
      await auth.flows.beginProvider('magic-link', { email: 'a@x.com' })
      const token = extractToken(channel.sent[0]?.url ?? '')
      const results = await Promise.allSettled([
        auth.flows.signIn({ providerId: 'magic-link', input: { token } }),
        auth.flows.signIn({ providerId: 'magic-link', input: { token } }),
      ])
      const fulfilled = results.filter((r) => r.status === 'fulfilled')
      const rejected = results.filter((r) => r.status === 'rejected')
      expect(fulfilled).toHaveLength(1)
      expect(rejected).toHaveLength(1)
      expect((rejected[0] as PromiseRejectedResult).reason).toMatchObject({ code: 'AUTH/RECOVERY_TOKEN_INVALID' })
    })

    it('expired token surfaces AUTH/RECOVERY_TOKEN_EXPIRED', async () => {
      const { auth, channel, adapter } = buildAuth({ autoCreate: true })
      await auth.flows.beginProvider('magic-link', { email: 'a@x.com' })
      const token = extractToken(channel.sent[0]?.url ?? '')
      const i = await adapter.identities.findByEmail('a@x.com', {})
      if (!i) throw new Error('identity missing')
      const creds = await adapter.credentials.listByIdentity(i.id, 'magic-link', {})
      const cred = creds[0]
      if (!cred) throw new Error('credential missing')
      ;(cred as { expiresAt?: number }).expiresAt = Date.now() - 1
      await expect(auth.flows.signIn({ providerId: 'magic-link', input: { token } })).rejects.toMatchObject({
        code: 'AUTH/RECOVERY_TOKEN_EXPIRED',
      })
    })

    it('bogus token surfaces AUTH/RECOVERY_TOKEN_INVALID', async () => {
      const { auth } = buildAuth({ autoCreate: true })
      await expect(auth.flows.signIn({ providerId: 'magic-link', input: { token: 'not-real' } })).rejects.toMatchObject(
        { code: 'AUTH/RECOVERY_TOKEN_INVALID' },
      )
    })

    describe('defensive guards against malformed adapter rows', () => {
      async function mintTokenAndGrabRow(): Promise<{
        auth: AuthEngine<MyProfile>
        adapter: AuthMemoryAdapter<MyProfile>
        token: string
        row: Awaited<ReturnType<AuthMemoryAdapter<MyProfile>['credentials']['findByHashedSecret']>>
      }> {
        const { auth, adapter, channel } = buildAuth({ autoCreate: true })
        await auth.flows.beginProvider('magic-link', { email: 'a@x.com' })
        const token = extractToken(channel.sent[0]?.url ?? '')
        const i = await adapter.identities.findByEmail('a@x.com', {})
        if (!i) throw new Error('identity missing')
        const creds = await adapter.credentials.listByIdentity(i.id, 'magic-link', {})
        const cred = creds[0]
        if (!cred) throw new Error('credential missing')
        const row = await adapter.credentials.findByHashedSecret(cred.secret, 'magic-link', {})
        return { auth, adapter, token, row }
      }

      it('non-numeric expiresAt (from a buggy adapter) is treated as expired (NaN-bypass defense)', async () => {
        const { auth, row, token } = await mintTokenAndGrabRow()
        if (!row) throw new Error('row missing')
        // Inject a malformed expiresAt that would have made
        // `expiresAt < now` evaluate `NaN < N === false` and let the
        // token be treated as fresh.
        // @ts-expect-error: SEC test intentionally violates the typed shape
        row.expiresAt = 'not-a-number'
        await expect(auth.flows.signIn({ providerId: 'magic-link', input: { token } })).rejects.toMatchObject({
          code: 'AUTH/RECOVERY_TOKEN_EXPIRED',
        })
      })

      it('revokedAt === 0 (legitimate epoch number) is now treated as revoked (previously slipped past `!revokedAt`)', async () => {
        const { auth, row, token } = await mintTokenAndGrabRow()
        if (!row) throw new Error('row missing')
        row.revokedAt = 0
        await expect(auth.flows.signIn({ providerId: 'magic-link', input: { token } })).rejects.toMatchObject({
          code: 'AUTH/RECOVERY_TOKEN_INVALID',
        })
      })

      it('revokedAt as a non-numeric value also surfaces as revoked', async () => {
        const { auth, row, token } = await mintTokenAndGrabRow()
        if (!row) throw new Error('row missing')
        // @ts-expect-error: SEC test intentionally violates the typed shape
        row.revokedAt = 'truthy-but-not-a-timestamp'
        await expect(auth.flows.signIn({ providerId: 'magic-link', input: { token } })).rejects.toMatchObject({
          code: 'AUTH/RECOVERY_TOKEN_INVALID',
        })
      })
    })
  })
})
