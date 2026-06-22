import { describe, expect, it, vi } from 'vitest'
import { AuthMemoryAdapter } from '../../../adapters/memory'
import { authRandomToken, authSha256, authTimingSafeEqual } from '../../../core/crypto'
import { AuthInMemoryEvents } from '../../../core/events'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { AuthSamlProvider, authSamlProvider } from '../index'

interface MyProfile {
  email: string
}

function ctxFor(adapter: AuthMemoryAdapter<MyProfile>) {
  return {
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    tenant: {},
    baseUrl: 'https://app.test',
    limiter: new AuthMemoryLimiter(),
    events: new AuthInMemoryEvents(),
    crypto: { authRandomToken, authSha256, authTimingSafeEqual },
  }
}

function makeClient(overrides: Partial<AuthSamlProvider.IClient> = {}): AuthSamlProvider.IClient {
  return {
    getAuthorizeUrlAsync: vi.fn(async () => 'https://idp.example/sso?SAMLRequest=AAA'),
    validatePostResponseAsync: vi.fn(async () => ({
      profile: { nameID: 'sso-user-1', email: 'user@x.com' } as AuthSamlProvider.IProfile,
      loggedOut: false,
    })),
    ...overrides,
  }
}

describe('samlProvider - construction guards', () => {
  it('refuses without client', () => {
    expect(() =>
      authSamlProvider({ callbackUrl: 'https://app/acs', onSignIn: async () => ({ identityId: 'x' }) } as never),
    ).toThrowError(expect.objectContaining({ code: 'AUTH/MISCONFIGURED' }))
  })

  it('refuses without callbackUrl', () => {
    expect(() =>
      authSamlProvider({
        client: makeClient(),
        callbackUrl: '',
        onSignIn: async () => ({ identityId: 'x' }),
      }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH/MISCONFIGURED' }))
  })

  it('refuses without onSignIn', () => {
    expect(() =>
      authSamlProvider({
        client: makeClient(),
        callbackUrl: 'https://app/acs',
      } as never),
    ).toThrowError(expect.objectContaining({ code: 'AUTH/MISCONFIGURED' }))
  })
})

describe('samlProvider - begin', () => {
  it('returns redirect intent with IdP URL', async () => {
    const adapter = new AuthMemoryAdapter<MyProfile>()
    const provider = authSamlProvider<MyProfile>({
      client: makeClient(),
      callbackUrl: 'https://app/acs',
      onSignIn: async () => ({ identityId: 'x' }),
    })
    const intents = await provider.begin(ctxFor(adapter), {
      relayState: 'csrf-token',
      host: 'https://app',
    })
    expect(intents).toHaveLength(1)
    expect(intents[0]!.type).toBe('redirect')
    if (intents[0]!.type !== 'redirect') return
    expect(intents[0]!.url).toContain('SAMLRequest')
  })

  it('begin missing relayState rejects MISCONFIGURED', async () => {
    const adapter = new AuthMemoryAdapter<MyProfile>()
    const provider = authSamlProvider<MyProfile>({
      client: makeClient(),
      callbackUrl: 'https://app/acs',
      onSignIn: async () => ({ identityId: 'x' }),
    })
    await expect(provider.begin(ctxFor(adapter), { relayState: '', host: 'https://app' })).rejects.toMatchObject({
      code: 'AUTH/MISCONFIGURED',
    })
  })
})

describe('samlProvider - complete', () => {
  it('validates SAMLResponse + invokes onSignIn + emits startSession (aal:2)', async () => {
    const adapter = new AuthMemoryAdapter<MyProfile>()
    const onSignIn = vi.fn(async () => ({ identityId: 'ident-7' }))
    const provider = authSamlProvider<MyProfile>({
      client: makeClient(),
      callbackUrl: 'https://app/acs',
      onSignIn,
    })
    const intents = await provider.complete(ctxFor(adapter), {
      SAMLResponse: 'BASE64ENCODEDXML',
    })
    expect(onSignIn).toHaveBeenCalledOnce()
    expect(intents).toHaveLength(1)
    expect(intents[0]!.type).toBe('startSession')
    if (intents[0]!.type !== 'startSession') return
    expect(intents[0]!.identityId).toBe('ident-7')
    expect(intents[0]!.aal).toBe(2)
    expect(intents[0]!.factors[0]!.method).toBe('oauth')
  })

  it('rejects empty SAMLResponse with PROVIDER_FAILED', async () => {
    const adapter = new AuthMemoryAdapter<MyProfile>()
    const provider = authSamlProvider<MyProfile>({
      client: makeClient(),
      callbackUrl: 'https://app/acs',
      onSignIn: async () => ({ identityId: 'x' }),
    })
    await expect(provider.complete(ctxFor(adapter), { SAMLResponse: '' })).rejects.toMatchObject({
      code: 'AUTH/PROVIDER_FAILED',
    })
  })

  it('rejects when IdP returns loggedOut response', async () => {
    const adapter = new AuthMemoryAdapter<MyProfile>()
    const provider = authSamlProvider<MyProfile>({
      client: makeClient({
        validatePostResponseAsync: async () => ({ profile: null, loggedOut: true }),
      }),
      callbackUrl: 'https://app/acs',
      onSignIn: async () => ({ identityId: 'x' }),
    })
    await expect(provider.complete(ctxFor(adapter), { SAMLResponse: 'XYZ' })).rejects.toMatchObject({
      code: 'AUTH/PROVIDER_FAILED',
    })
  })

  it('client throw surfaces as PROVIDER_FAILED + detail', async () => {
    const adapter = new AuthMemoryAdapter<MyProfile>()
    const provider = authSamlProvider<MyProfile>({
      client: makeClient({
        validatePostResponseAsync: async () => {
          throw new Error('signature-invalid')
        },
      }),
      callbackUrl: 'https://app/acs',
      onSignIn: async () => ({ identityId: 'x' }),
    })
    await expect(provider.complete(ctxFor(adapter), { SAMLResponse: 'XYZ' })).rejects.toMatchObject({
      code: 'AUTH/PROVIDER_FAILED',
    })
  })
})
