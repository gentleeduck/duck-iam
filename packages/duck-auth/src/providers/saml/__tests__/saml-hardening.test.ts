import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256, timingSafeEqual } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import { Identities } from '~/core/identities'
import { MemoryLimiter } from '~/limiters/memory'
import { identityInput } from '~/test/store-inputs'
import { Saml, saml } from '../index'

interface MyProfile extends Identities.ProfileMetadataBase {}

function ctxFor(adapter: MemoryAdapter<MyProfile>, events?: InMemoryEvents) {
  return {
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    tenant: {},
    baseUrl: 'https://app.test',
    limiter: new MemoryLimiter(),
    events: events ?? new InMemoryEvents(),
    crypto: { authRandomToken: randomToken, authSha256: sha256, authTimingSafeEqual: timingSafeEqual },
  }
}

function makeClient(overrides: Partial<Saml.Client> = {}): Saml.Client {
  return {
    getAuthorizeUrlAsync: vi.fn(async () => 'https://idp.example/sso?SAMLRequest=AAA'),
    validatePostResponseAsync: vi.fn(async () => ({
      profile: { nameID: 'sso-user-1', email: 'user@x.com' } as Saml.Profile,
      loggedOut: false,
    })),
    ...overrides,
  }
}

describe('samlProvider - input caps', () => {
  let adapter: MemoryAdapter<MyProfile>

  beforeEach(() => {
    adapter = new MemoryAdapter<MyProfile>()
  })

  describe('begin', () => {
    it('rejects oversize relayState (>256 chars)', async () => {
      const client = makeClient()
      const provider = saml({
        client,
        callbackUrl: 'https://app/acs',
        onSignIn: async () => ({ identityId: 'x' }),
      })
      await expect(
        provider.begin(ctxFor(adapter), { relayState: 'A'.repeat(257), host: 'app.test' }),
      ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
      expect(client.getAuthorizeUrlAsync).not.toHaveBeenCalled()
    })

    it('accepts relayState at the cap (256 chars)', async () => {
      const client = makeClient()
      const provider = saml({
        client,
        callbackUrl: 'https://app/acs',
        onSignIn: async () => ({ identityId: 'x' }),
      })
      const intents = await provider.begin(ctxFor(adapter), { relayState: 'A'.repeat(256), host: 'app.test' })
      expect(intents[0]!.type).toBe('redirect')
    })

    it('rejects empty relayState', async () => {
      const client = makeClient()
      const provider = saml({
        client,
        callbackUrl: 'https://app/acs',
        onSignIn: async () => ({ identityId: 'x' }),
      })
      await expect(provider.begin(ctxFor(adapter), { relayState: '', host: 'app.test' })).rejects.toMatchObject({
        code: 'AUTH_MISCONFIGURED',
      })
    })

    it('rejects oversize host (>253 chars)', async () => {
      const client = makeClient()
      const provider = saml({
        client,
        callbackUrl: 'https://app/acs',
        onSignIn: async () => ({ identityId: 'x' }),
      })
      await expect(provider.begin(ctxFor(adapter), { relayState: 'rs', host: 'a'.repeat(254) })).rejects.toMatchObject({
        code: 'AUTH_MISCONFIGURED',
      })
      expect(client.getAuthorizeUrlAsync).not.toHaveBeenCalled()
    })

    it('rejects empty host', async () => {
      const client = makeClient()
      const provider = saml({
        client,
        callbackUrl: 'https://app/acs',
        onSignIn: async () => ({ identityId: 'x' }),
      })
      await expect(provider.begin(ctxFor(adapter), { relayState: 'rs', host: '' })).rejects.toMatchObject({
        code: 'AUTH_MISCONFIGURED',
      })
    })

    it('rejects non-string relayState without crashing', async () => {
      const client = makeClient()
      const provider = saml({
        client,
        callbackUrl: 'https://app/acs',
        onSignIn: async () => ({ identityId: 'x' }),
      })
      await expect(
        // simulate a malformed body parsed as { relayState: 42, host: 'app.test' }
        provider.begin(ctxFor(adapter), { relayState: 42 as unknown as string, host: 'app.test' }),
      ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
    })
  })

  describe('complete - SAMLResponse cap', () => {
    it('rejects oversize SAMLResponse (>1 MiB) BEFORE calling validatePostResponseAsync', async () => {
      const client = makeClient()
      const provider = saml({
        client,
        callbackUrl: 'https://app/acs',
        onSignIn: async () => ({ identityId: 'x' }),
      })
      const oversize = 'A'.repeat(1_048_577)
      await expect(provider.complete(ctxFor(adapter), { SAMLResponse: oversize })).rejects.toMatchObject({
        code: 'AUTH_PROVIDER_FAILED',
        meta: { detail: 'invalid SAMLResponse' },
      })
      expect(client.validatePostResponseAsync).not.toHaveBeenCalled()
    })

    it('accepts SAMLResponse exactly at 1 MiB', async () => {
      const adapterInner = new MemoryAdapter<MyProfile>()
      const ident = await adapterInner.identities.create(
        identityInput({ profile: { email: 'u@x.com', username: 'u' }, providers: [] }),
      )
      const client = makeClient()
      const provider = saml({
        client,
        callbackUrl: 'https://app/acs',
        onSignIn: async () => ({ identityId: ident.id }),
      })
      const okSize = 'A'.repeat(1_048_576)
      const intents = await provider.complete(ctxFor(adapterInner), { SAMLResponse: okSize })
      expect(intents[0]!.type).toBe('startSession')
      expect(client.validatePostResponseAsync).toHaveBeenCalledOnce()
    })

    it('rejects empty SAMLResponse', async () => {
      const client = makeClient()
      const provider = saml({
        client,
        callbackUrl: 'https://app/acs',
        onSignIn: async () => ({ identityId: 'x' }),
      })
      await expect(provider.complete(ctxFor(adapter), { SAMLResponse: '' })).rejects.toMatchObject({
        code: 'AUTH_PROVIDER_FAILED',
        meta: { detail: 'invalid SAMLResponse' },
      })
      expect(client.validatePostResponseAsync).not.toHaveBeenCalled()
    })

    it('rejects non-string SAMLResponse without crashing', async () => {
      const client = makeClient()
      const provider = saml({
        client,
        callbackUrl: 'https://app/acs',
        onSignIn: async () => ({ identityId: 'x' }),
      })
      await expect(
        provider.complete(ctxFor(adapter), { SAMLResponse: null as unknown as string }),
      ).rejects.toMatchObject({
        code: 'AUTH_PROVIDER_FAILED',
        meta: { detail: 'invalid SAMLResponse' },
      })
    })
  })

  describe('complete - IdP error-message redaction', () => {
    it('does NOT echo node-saml error message to the wire detail', async () => {
      const client = makeClient({
        validatePostResponseAsync: vi.fn(async () => {
          throw new Error('<saml:Assertion>secret-attribute</saml:Assertion> signature invalid at xpath /foo/bar')
        }),
      })
      const provider = saml({
        client,
        callbackUrl: 'https://app/acs',
        onSignIn: async () => ({ identityId: 'x' }),
      })
      try {
        await provider.complete(ctxFor(adapter), { SAMLResponse: '<SAMLResponse/>' })
        throw new Error('expected throw')
      } catch (err) {
        const e = err as { code: string; meta: { detail: string } }
        expect(e.code).toBe('AUTH_PROVIDER_FAILED')
        expect(e.meta.detail).toBe('SAMLResponse validation failed')
        // The leaky bits MUST NOT appear in the wire detail.
        expect(e.meta.detail).not.toContain('<saml:Assertion>')
        expect(e.meta.detail).not.toContain('secret-attribute')
        expect(e.meta.detail).not.toContain('/foo/bar')
      }
    })

    it('emits the real reason on events.signin.failed for operator visibility', async () => {
      const events = new InMemoryEvents()
      const seen: Array<{ providerId: string; reason: string }> = []
      events.on('signin.failed', (payload) => {
        seen.push({ providerId: payload.providerId, reason: payload.reason })
      })
      const client = makeClient({
        validatePostResponseAsync: vi.fn(async () => {
          throw new Error('signature mismatch - Audience http://wrong')
        }),
      })
      const provider = saml({
        client,
        callbackUrl: 'https://app/acs',
        onSignIn: async () => ({ identityId: 'x' }),
      })
      await expect(
        provider.complete(ctxFor(adapter, events), { SAMLResponse: '<SAMLResponse/>' }),
      ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
      expect(seen).toHaveLength(1)
      expect(seen[0]!.providerId).toBe('saml')
      // The full reason DOES reach operators.
      expect(seen[0]!.reason).toContain('signature mismatch')
      expect(seen[0]!.reason).toContain('Audience http://wrong')
    })

    it('non-Error throws still emit and surface generic detail (no String() leak)', async () => {
      const events = new InMemoryEvents()
      const seen: string[] = []
      events.on('signin.failed', (payload) => {
        seen.push(payload.reason)
      })
      const client = makeClient({
        validatePostResponseAsync: vi.fn(async () => {
          throw 'internal-saml-state-blob'
        }),
      })
      const provider = saml({
        client,
        callbackUrl: 'https://app/acs',
        onSignIn: async () => ({ identityId: 'x' }),
      })
      try {
        await provider.complete(ctxFor(adapter, events), { SAMLResponse: '<SAMLResponse/>' })
        throw new Error('expected throw')
      } catch (err) {
        const e = err as { meta: { detail: string } }
        expect(e.meta.detail).toBe('SAMLResponse validation failed')
        expect(e.meta.detail).not.toContain('internal-saml-state-blob')
      }
      expect(seen).toEqual(['internal-saml-state-blob'])
    })
  })

  describe('complete - nameID structural validation', () => {
    it('rejects profile with empty nameID (JIT-collapse defense)', async () => {
      const client = makeClient({
        validatePostResponseAsync: vi.fn(async () => ({
          profile: { nameID: '', email: 'u@x.com' } as Saml.Profile,
          loggedOut: false,
        })),
      })
      const onSignIn = vi.fn(async () => ({ identityId: 'x' }))
      const provider = saml({ client, callbackUrl: 'https://app/acs', onSignIn })
      await expect(provider.complete(ctxFor(adapter), { SAMLResponse: '<SAMLResponse/>' })).rejects.toMatchObject({
        code: 'AUTH_PROVIDER_FAILED',
        meta: { detail: 'invalid SAML profile' },
      })
      // onSignIn must NOT fire when nameID is invalid - otherwise
      // app code receives an attacker-shaped profile and provisions
      // an identity from it.
      expect(onSignIn).not.toHaveBeenCalled()
    })

    it('rejects profile with non-string nameID', async () => {
      const client = makeClient({
        validatePostResponseAsync: vi.fn(async () => ({
          profile: { nameID: 42 as unknown as string } as Saml.Profile,
          loggedOut: false,
        })),
      })
      const onSignIn = vi.fn(async () => ({ identityId: 'x' }))
      const provider = saml({ client, callbackUrl: 'https://app/acs', onSignIn })
      await expect(provider.complete(ctxFor(adapter), { SAMLResponse: '<SAMLResponse/>' })).rejects.toMatchObject({
        code: 'AUTH_PROVIDER_FAILED',
        meta: { detail: 'invalid SAML profile' },
      })
      expect(onSignIn).not.toHaveBeenCalled()
    })

    it('emits signin.failed when profile is structurally invalid', async () => {
      const events = new InMemoryEvents()
      const seen: string[] = []
      events.on('signin.failed', (payload) => {
        seen.push(payload.reason)
      })
      const client = makeClient({
        validatePostResponseAsync: vi.fn(async () => ({
          profile: { nameID: '' } as Saml.Profile,
          loggedOut: false,
        })),
      })
      const provider = saml({
        client,
        callbackUrl: 'https://app/acs',
        onSignIn: async () => ({ identityId: 'x' }),
      })
      await expect(
        provider.complete(ctxFor(adapter, events), { SAMLResponse: '<SAMLResponse/>' }),
      ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
      expect(seen).toEqual(['saml profile missing/invalid nameID'])
    })

    it('valid nameID flows through to onSignIn unchanged', async () => {
      const adapterInner = new MemoryAdapter<MyProfile>()
      const ident = await adapterInner.identities.create(
        identityInput({ profile: { email: 'u@x.com', username: 'u' }, providers: [] }),
      )
      const client = makeClient({
        validatePostResponseAsync: vi.fn(async () => ({
          profile: { nameID: 'legit-sso-id-123', email: 'u@x.com' } as Saml.Profile,
          loggedOut: false,
        })),
      })
      const onSignIn = vi.fn(async () => ({ identityId: ident.id }))
      const provider = saml({ client, callbackUrl: 'https://app/acs', onSignIn })
      const intents = await provider.complete(ctxFor(adapterInner), { SAMLResponse: '<SAMLResponse/>' })
      expect(intents[0]!.type).toBe('startSession')
      expect(onSignIn).toHaveBeenCalledOnce()
    })
  })
})
