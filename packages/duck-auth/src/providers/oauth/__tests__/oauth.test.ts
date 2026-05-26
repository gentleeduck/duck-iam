import { describe, expect, it, vi } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { AuthRoot } from '../../../core/auth'
import { ScryptHasher } from '../../../core/password/scrypt'
import { CookieTransport } from '../../../core/transport/cookie'
import { MemoryLimiter } from '../../../limiters/memory'
import { OAuthClient } from '../core/client'
import { generatePkce } from '../core/pkce'
import { oauthProvider } from '../core/provider'
import { buildState, signState, verifyState } from '../core/state'

interface MyProfile {
  email: string
  name?: string
}

describe('OAuth core - PKCE + state', () => {
  it('generatePkce produces an S256 challenge derived from the verifier', () => {
    const { verifier, challenge, method } = generatePkce()
    expect(method).toBe('S256')
    expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(challenge).not.toBe(verifier)
  })

  it('signState / verifyState roundtrip', () => {
    const payload = buildState('oauth:google', 'verifier-xyz')
    const state = signState(payload, 'secret')
    const back = verifyState(state, 'secret')
    expect(back?.providerId).toBe('oauth:google')
    expect(back?.verifier).toBe('verifier-xyz')
    expect(back?.nonce).toBe(payload.nonce)
  })

  it('verifyState rejects tampered signature', () => {
    const payload = buildState('oauth:google', 'v')
    const state = signState(payload, 'secret')
    const tampered = `${state.slice(0, -3)}xxx`
    expect(verifyState(tampered, 'secret')).toBeNull()
  })

  it('verifyState rejects wrong secret', () => {
    const state = signState(buildState('oauth:google', 'v'), 'secret-a')
    expect(verifyState(state, 'secret-b')).toBeNull()
  })

  it('verifyState rejects expired state past maxAgeMs', () => {
    const payload = { ...buildState('oauth:google', 'v'), iat: Date.now() - 11 * 60 * 1000 }
    const state = signState(payload, 'secret')
    expect(verifyState(state, 'secret')).toBeNull()
  })
})

describe('OAuthClient.buildAuthorizeUrl', () => {
  it('emits the RFC 6749 authorization URL with PKCE + state', async () => {
    const client = new OAuthClient({
      clientId: 'cid',
      endpoints: {
        authorizationEndpoint: 'https://idp.example.com/authorize',
        tokenEndpoint: 'https://idp.example.com/token',
      },
      scopes: ['openid', 'email'],
    })
    const url = await client.buildAuthorizeUrl({
      redirectUri: 'https://app/cb',
      state: 'state-abc',
      codeChallenge: 'cc-xyz',
    })
    const u = new URL(url)
    expect(u.origin).toBe('https://idp.example.com')
    expect(u.searchParams.get('response_type')).toBe('code')
    expect(u.searchParams.get('client_id')).toBe('cid')
    expect(u.searchParams.get('redirect_uri')).toBe('https://app/cb')
    expect(u.searchParams.get('scope')).toBe('openid email')
    expect(u.searchParams.get('state')).toBe('state-abc')
    expect(u.searchParams.get('code_challenge')).toBe('cc-xyz')
    expect(u.searchParams.get('code_challenge_method')).toBe('S256')
  })
})

describe('oauthProvider - generic end-to-end (mocked IdP)', () => {
  function buildAuth(fakeIdp: typeof globalThis.fetch) {
    const adapter = new MemoryAuthAdapter<MyProfile>()
    const auth = new AuthRoot<MyProfile>({
      baseUrl: 'https://app',
      transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
      stores: {
        identities: adapter.identities,
        sessions: adapter.sessions,
        credentials: adapter.credentials,
      },
      limiter: new MemoryLimiter({ max: 10, windowMs: 60_000 }),
      passwords: { hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) },
    })

    const client = new OAuthClient({
      clientId: 'cid',
      clientSecret: 'csec',
      endpoints: {
        authorizationEndpoint: 'https://idp/authorize',
        tokenEndpoint: 'https://idp/token',
        userinfoEndpoint: 'https://idp/userinfo',
      },
      scopes: ['openid', 'email', 'profile'],
      fetch: fakeIdp,
    })

    auth.providers.register(
      oauthProvider<MyProfile>({
        providerId: 'fakeoidc',
        client,
        endpoints: {
          authorizationEndpoint: 'https://idp/authorize',
          tokenEndpoint: 'https://idp/token',
          userinfoEndpoint: 'https://idp/userinfo',
        },
        redirectUri: 'https://app/cb',
        stateSigningSecret: 'super-secret',
        async fetchProfile(tokens, c) {
          const info = (await c.userinfo(tokens.access_token)) as {
            sub: string
            email: string
            name?: string
          }
          return { sub: info.sub, email: info.email, name: info.name }
        },
      }),
    )
    return { auth, adapter }
  }

  it('begin returns a redirect intent containing the authorize URL', async () => {
    const fetchImpl = vi.fn() as unknown as typeof globalThis.fetch
    const { auth } = buildAuth(fetchImpl)
    const intents = await auth.flows.beginProvider('oauth:fakeoidc', {})
    expect(intents).toHaveLength(1)
    const intent = intents[0]!
    expect(intent.type).toBe('redirect')
    if (intent.type === 'redirect') {
      const u = new URL(intent.url)
      expect(u.origin).toBe('https://idp')
      expect(u.searchParams.get('code_challenge_method')).toBe('S256')
      expect(u.searchParams.get('state')).toBeTruthy()
    }
  })

  it('complete exchanges code, fetches userinfo, creates identity, returns startSession (auto-create branch)', async () => {
    const fetchImpl = vi.fn(async (url: string, _init?: RequestInit) => {
      if (url.startsWith('https://idp/token')) {
        return new Response(
          JSON.stringify({
            access_token: 'at-xyz',
            token_type: 'Bearer',
            expires_in: 3600,
            refresh_token: 'rt-xyz',
            id_token: 'id-xyz',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        )
      }
      if (url.startsWith('https://idp/userinfo')) {
        return new Response(JSON.stringify({ sub: 'idp-user-1', email: 'new@x.com', name: 'New User' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      }
      throw new Error(`unexpected url ${url}`)
    }) as unknown as typeof globalThis.fetch
    const { auth, adapter } = buildAuth(fetchImpl)

    // Build a real state via begin (to round-trip the PKCE verifier).
    const beginIntents = await auth.flows.beginProvider('oauth:fakeoidc', {})
    const url = new URL((beginIntents[0] as { url: string }).url)
    const state = url.searchParams.get('state') ?? ''

    const result = await auth.flows.signIn({
      providerId: 'oauth:fakeoidc',
      input: { code: 'authcode-abc', state },
    })

    expect(result.session.factors[0]?.method).toBe('oauth')
    const identity = await adapter.identities.findByEmail('new@x.com', {})
    expect(identity).not.toBeNull()
    expect(identity?.providers.some((p) => p.providerId === 'oauth:fakeoidc' && p.providerSub === 'idp-user-1')).toBe(
      true,
    )
    // Refresh token persisted, hashed.
    const oauthCreds = await adapter.credentials.listByIdentity(identity?.id ?? '', 'oauth', {})
    expect(oauthCreds[0]?.secret).toMatch(/^[0-9a-f]{64}$/)
    expect((oauthCreds[0]?.metadata as { familyId: string }).familyId).toContain('oauth:fakeoidc:idp-user-1')
  })

  it('complete with tampered state surfaces AUTH/OAUTH_STATE_MISMATCH', async () => {
    const fetchImpl = vi.fn() as unknown as typeof globalThis.fetch
    const { auth } = buildAuth(fetchImpl)
    await expect(
      auth.flows.signIn({
        providerId: 'oauth:fakeoidc',
        input: { code: 'authcode', state: 'tampered.state' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH/OAUTH_STATE_MISMATCH' })
  })

  it('complete with state from a different provider surfaces AUTH/OAUTH_STATE_MISMATCH', async () => {
    const fetchImpl = vi.fn() as unknown as typeof globalThis.fetch
    const { auth } = buildAuth(fetchImpl)
    // Forge a state signed correctly but for a different providerId.
    const payload = buildState('oauth:google', 'v')
    const state = signState(payload, 'super-secret')
    await expect(
      auth.flows.signIn({
        providerId: 'oauth:fakeoidc',
        input: { code: 'x', state },
      }),
    ).rejects.toMatchObject({ code: 'AUTH/OAUTH_STATE_MISMATCH' })
  })

  it('complete with second sign-in by same sub returns existing identity', async () => {
    const fetchImpl = vi.fn(async (url: string) => {
      if (url.startsWith('https://idp/token')) {
        return new Response(JSON.stringify({ access_token: 'at', token_type: 'Bearer', refresh_token: 'rt' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      }
      return new Response(JSON.stringify({ sub: 'sub-1', email: 'a@x.com', name: 'A' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    }) as unknown as typeof globalThis.fetch
    const { auth, adapter } = buildAuth(fetchImpl)

    const begin1 = await auth.flows.beginProvider('oauth:fakeoidc', {})
    const state1 = new URL((begin1[0] as { url: string }).url).searchParams.get('state') ?? ''
    await auth.flows.signIn({ providerId: 'oauth:fakeoidc', input: { code: 'c1', state: state1 } })
    const identitiesBefore = await adapter.identities.findByEmail('a@x.com', {})
    expect(identitiesBefore).not.toBeNull()

    const begin2 = await auth.flows.beginProvider('oauth:fakeoidc', {})
    const state2 = new URL((begin2[0] as { url: string }).url).searchParams.get('state') ?? ''
    const r2 = await auth.flows.signIn({ providerId: 'oauth:fakeoidc', input: { code: 'c2', state: state2 } })
    expect(r2.session.identityId).toBe(identitiesBefore?.id)
  })
})
