import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { AuthRoot } from '../../../core/auth'
import { CookieTransport } from '../../../core/transport/cookie'
import type { Channel } from '../../../core/types/channel'
import { MemoryLimiter } from '../../../limiters/memory'
import { magicLink } from '../index'

interface MyProfile {
  email: string
}

function fakeChannel(): Channel.IChannel & { sent: Array<{ to: string; url: string }> } {
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

function buildAuth(opts: { autoCreate?: boolean; channel?: Channel.IChannel } = {}): {
  auth: AuthRoot<MyProfile>
  adapter: MemoryAuthAdapter<MyProfile>
  channel: Channel.IChannel & { sent: Array<{ to: string; url: string }> }
} {
  const adapter = new MemoryAuthAdapter<MyProfile>()
  const channel = (opts.channel as Channel.IChannel & { sent: Array<{ to: string; url: string }> }) ?? fakeChannel()
  const auth = new AuthRoot<MyProfile>({
    baseUrl: 'https://app.example.com',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 3, windowMs: 60_000 }),
  })
  auth.providers.register(
    magicLink<MyProfile>({
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

    it('channel send failure surfaces AUTH/PROVIDER_FAILED', async () => {
      const broken: Channel.IChannel = {
        kind: 'email',
        id: 'broken',
        async send() {
          return { ok: false, error: 'smtp down' }
        },
      }
      const { auth } = buildAuth({ channel: broken })
      await auth.identities.create({ profile: { email: 'a@x.com' } })
      await expect(auth.flows.beginProvider('magic-link', { email: 'a@x.com' })).rejects.toMatchObject({
        code: 'AUTH/PROVIDER_FAILED',
        meta: { providerId: 'magic-link' },
      })
    })

    it('missing channel surfaces AUTH/MISCONFIGURED', async () => {
      const { auth } = buildAuth()
      await auth.identities.create({ profile: { email: 'a@x.com' } })
      await expect(auth.flows.beginProvider('magic-link', { email: 'a@x.com', channel: 'sms' })).rejects.toMatchObject({
        code: 'AUTH/MISCONFIGURED',
      })
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
      expect(result.session.factors[0]?.method).toBe('magic-link')
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
  })
})
