import { createHmac } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import { AuthMemoryAdapter } from '../../../adapters/memory'
import { AuthEngine } from '../../../core/engine'
import { AuthScryptHasher } from '../../../core/password/scrypt'
import { AuthCookieTransport } from '../../../core/transport/cookie'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { AuthOAuthClient } from '../core/client'
import { authGeneratePkce } from '../core/pkce'
import { oauthProvider } from '../core/provider'
import { authBuildState, authVerifyState, signState } from '../core/state'

/**
 * SEC helper: mint a properly-signed state string from a caller-supplied
 * (and possibly malformed) payload. Signature is correct so the verifier
 * reaches the claim-parsing path - exercises the runtime validator that
 * defends against missing/non-typed payload fields.
 */
function mintRawState(payload: unknown, secret: string): string {
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url')
  const sig = createHmac('sha256', secret).update(body).digest('base64url')
  return `${body}.${sig}`
}

interface MyProfile {
  email: string
  name?: string
}

describe('OAuth core - PKCE + state', () => {
  it('authGeneratePkce produces an S256 challenge derived from the verifier', () => {
    const { verifier, challenge, method } = authGeneratePkce()
    expect(method).toBe('S256')
    expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(challenge).not.toBe(verifier)
  })

  it('signState / authVerifyState roundtrip', () => {
    const payload = authBuildState('oauth:authGoogle', 'verifier-xyz')
    const state = signState(payload, 'secret')
    const back = authVerifyState(state, 'secret')
    expect(back?.providerId).toBe('oauth:authGoogle')
    expect(back?.verifier).toBe('verifier-xyz')
    expect(back?.nonce).toBe(payload.nonce)
  })

  it('authVerifyState rejects tampered signature', () => {
    const payload = authBuildState('oauth:authGoogle', 'v')
    const state = signState(payload, 'secret')
    const tampered = `${state.slice(0, -3)}xxx`
    expect(authVerifyState(tampered, 'secret')).toBeNull()
  })

  it('authVerifyState rejects wrong secret', () => {
    const state = signState(authBuildState('oauth:authGoogle', 'v'), 'secret-a')
    expect(authVerifyState(state, 'secret-b')).toBeNull()
  })

  it('authVerifyState rejects expired state past maxAgeMs', () => {
    const payload = { ...authBuildState('oauth:authGoogle', 'v'), iat: Date.now() - 11 * 60 * 1000 }
    const state = signState(payload, 'secret')
    expect(authVerifyState(state, 'secret')).toBeNull()
  })

  describe('authVerifyState - SEC: payload validation', () => {
    const SECRET = 'secret'
    const base = authBuildState('oauth:authGoogle', 'verifier-xyz')

    it('rejects payload whose iat is missing (would bypass expiry via NaN math)', () => {
      const { iat, ...noIat } = base
      void iat
      expect(authVerifyState(mintRawState(noIat, SECRET), SECRET)).toBeNull()
    })

    it('rejects payload whose iat is a string', () => {
      expect(authVerifyState(mintRawState({ ...base, iat: String(base.iat) }, SECRET), SECRET)).toBeNull()
    })

    it('rejects payload whose providerId is a non-string (would skew downstream callback check)', () => {
      expect(authVerifyState(mintRawState({ ...base, providerId: { evil: 'object' } }, SECRET), SECRET)).toBeNull()
    })

    it('rejects payload whose verifier is a non-string (would corrupt PKCE token exchange)', () => {
      expect(authVerifyState(mintRawState({ ...base, verifier: 42 }, SECRET), SECRET)).toBeNull()
    })

    it('rejects payload whose nonce is a non-string (would weaken one-time-use guarantee)', () => {
      expect(authVerifyState(mintRawState({ ...base, nonce: null }, SECRET), SECRET)).toBeNull()
    })

    it('rejects payload whose returnTo is a non-string (open-redirect defense)', () => {
      expect(authVerifyState(mintRawState({ ...base, returnTo: { url: '/evil' } }, SECRET), SECRET)).toBeNull()
    })

    it('rejects payload whose returnTo is oversize (URL-bomb defense)', () => {
      // The state is HMAC-signed and carried in the OAuth provider URL.
      // An attacker who can call begin() with a massive returnTo would
      // mint state cookies / URLs that overflow browser/provider limits
      // and cause unpredictable failures. Cap at 2048.
      const huge = 'x'.repeat(2049)
      expect(authVerifyState(mintRawState({ ...base, returnTo: huge }, SECRET), SECRET)).toBeNull()
    })

    it('accepts returnTo at the exact cap (2048 chars)', () => {
      const max = 'x'.repeat(2048)
      const result = authVerifyState(mintRawState({ ...base, returnTo: max }, SECRET), SECRET)
      expect(result?.returnTo).toBe(max)
    })

    it('rejects payload that is a JSON array (not an object)', () => {
      expect(authVerifyState(mintRawState(['not', 'an', 'object'], SECRET), SECRET)).toBeNull()
    })

    it('rejects a state string with extra dot-separated segments (no longer relies on parts cast)', () => {
      const goodState = signState(base, SECRET)
      expect(authVerifyState(`${goodState}.extra`, SECRET)).toBeNull()
    })

    it('rejects an oversize state parameter (>8192 chars, resource amplification defense)', () => {
      // Without the top-level cap, an attacker could send a multi-MB
      // state and force a base64 decode + JSON.parse over the whole
      // blob (regardless of HMAC outcome the decode still runs).
      const huge = 'x'.repeat(8193)
      expect(authVerifyState(huge, SECRET)).toBeNull()
    })

    it('rejects a non-string state without crashing on .split (typeof guard)', () => {
      expect(authVerifyState(undefined as unknown as string, SECRET)).toBeNull()
      expect(authVerifyState(42 as unknown as string, SECRET)).toBeNull()
      expect(authVerifyState('' as string, SECRET)).toBeNull()
    })

    it('accepts a state at the exact cap (8192 chars) - well-formed signed state at boundary still validates', () => {
      // Build a payload large enough that the signed state lands near
      // the cap, confirming a legitimate (if borderline) state passes.
      const longReturnTo = 'x'.repeat(2048)
      const state = signState({ ...base, returnTo: longReturnTo }, SECRET)
      // The signed state is well under 8192 in practice (~3K with
      // returnTo at cap); verify it still validates.
      expect(state.length).toBeLessThan(8192)
      expect(authVerifyState(state, SECRET)?.returnTo).toBe(longReturnTo)
    })
  })
})

describe('AuthOAuthClient - SEC: token response validation', () => {
  function clientWithResponse(body: unknown, status = 200): AuthOAuthClient {
    return new AuthOAuthClient({
      clientId: 'cid',
      endpoints: {
        authorizationEndpoint: 'https://idp/authorize',
        tokenEndpoint: 'https://idp/token',
        userinfoEndpoint: 'https://idp/userinfo',
      },
      scopes: ['openid'],
      fetch: async () =>
        new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }),
    })
  }

  it('exchangeCode rejects non-object response (e.g. provider returns a JSON array)', async () => {
    const client = clientWithResponse(['not', 'an', 'object'])
    await expect(
      client.exchangeCode({ code: 'c', redirectUri: 'https://app/cb', codeVerifier: 'v' }),
    ).rejects.toMatchObject({ code: 'AUTH/PROVIDER_FAILED' })
  })

  it('exchangeCode rejects response missing access_token', async () => {
    const client = clientWithResponse({ token_type: 'Bearer', expires_in: 3600 })
    await expect(
      client.exchangeCode({ code: 'c', redirectUri: 'https://app/cb', codeVerifier: 'v' }),
    ).rejects.toMatchObject({ code: 'AUTH/PROVIDER_FAILED' })
  })

  it('exchangeCode rejects non-string access_token (would corrupt Bearer header downstream)', async () => {
    const client = clientWithResponse({ access_token: 42, token_type: 'Bearer' })
    await expect(
      client.exchangeCode({ code: 'c', redirectUri: 'https://app/cb', codeVerifier: 'v' }),
    ).rejects.toMatchObject({ code: 'AUTH/PROVIDER_FAILED' })
  })

  it('exchangeCode rejects non-numeric expires_in (would have stored NaN expiry into family metadata)', async () => {
    const client = clientWithResponse({ access_token: 'at', token_type: 'Bearer', expires_in: '3600' })
    await expect(
      client.exchangeCode({ code: 'c', redirectUri: 'https://app/cb', codeVerifier: 'v' }),
    ).rejects.toMatchObject({ code: 'AUTH/PROVIDER_FAILED' })
  })

  it('exchangeCode rejects non-string refresh_token', async () => {
    const client = clientWithResponse({ access_token: 'at', token_type: 'Bearer', refresh_token: { evil: true } })
    await expect(
      client.exchangeCode({ code: 'c', redirectUri: 'https://app/cb', codeVerifier: 'v' }),
    ).rejects.toMatchObject({ code: 'AUTH/PROVIDER_FAILED' })
  })

  it('refresh rejects malformed response', async () => {
    const client = clientWithResponse({ token_type: 'Bearer' })
    await expect(client.refresh('rt')).rejects.toMatchObject({ code: 'AUTH/PROVIDER_FAILED' })
  })

  it('exchangeCode rejects invalid JSON body', async () => {
    const client = new AuthOAuthClient({
      clientId: 'cid',
      endpoints: { authorizationEndpoint: 'https://idp/a', tokenEndpoint: 'https://idp/t' },
      scopes: ['openid'],
      fetch: async () => new Response('not json at all', { status: 200 }),
    })
    await expect(
      client.exchangeCode({ code: 'c', redirectUri: 'https://app/cb', codeVerifier: 'v' }),
    ).rejects.toMatchObject({ code: 'AUTH/PROVIDER_FAILED' })
  })

  it('userinfo rejects non-object response body', async () => {
    const client = clientWithResponse('a string body')
    await expect(client.userinfo('at')).rejects.toMatchObject({ code: 'AUTH/PROVIDER_FAILED' })
  })
})

describe('AuthOAuthClient.buildAuthorizeUrl', () => {
  it('emits the RFC 6749 authorization URL with PKCE + state', async () => {
    const client = new AuthOAuthClient({
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
    const adapter = new AuthMemoryAdapter<MyProfile>()
    const auth = new AuthEngine<MyProfile>({
      baseUrl: 'https://app',
      transport: new AuthCookieTransport({ secure: false, name: 'duck-sid' }),
      stores: {
        identities: adapter.identities,
        sessions: adapter.sessions,
        credentials: adapter.credentials,
      },
      limiter: new AuthMemoryLimiter({ max: 10, windowMs: 60_000 }),
      passwords: { hasher: new AuthScryptHasher({ N: 1 << 10, keylen: 32 }) },
    })

    const client = new AuthOAuthClient({
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

    expect(result.session!.factors[0]?.method).toBe('oauth')
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

  it('complete rejects oversize code (>2048 chars) BEFORE forwarding to IdP (outbound resource amplification defense)', async () => {
    const fetchImpl = vi.fn() as unknown as typeof globalThis.fetch
    const { auth } = buildAuth(fetchImpl)
    const huge = 'x'.repeat(2049)
    await expect(
      auth.flows.signIn({
        providerId: 'oauth:fakeoidc',
        input: { code: huge, state: 'whatever' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH/PROVIDER_FAILED' })
    // Library MUST not have fired any fetch - code rejected before exchange.
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('complete rejects empty code (defensive)', async () => {
    const fetchImpl = vi.fn() as unknown as typeof globalThis.fetch
    const { auth } = buildAuth(fetchImpl)
    await expect(
      auth.flows.signIn({
        providerId: 'oauth:fakeoidc',
        input: { code: '', state: 'whatever' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH/PROVIDER_FAILED' })
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('complete with state from a different provider surfaces AUTH/OAUTH_STATE_MISMATCH', async () => {
    const fetchImpl = vi.fn() as unknown as typeof globalThis.fetch
    const { auth } = buildAuth(fetchImpl)
    // Forge a state signed correctly but for a different providerId.
    const payload = authBuildState('oauth:authGoogle', 'v')
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
    expect(r2.session!.identityId).toBe(identitiesBefore?.id)
  })
})

describe('oauthProvider - redirectUri construction guard', () => {
  const baseOpts = {
    providerId: 'fakeoidc',
    client: new AuthOAuthClient({
      clientId: 'cid',
      clientSecret: 'csec',
      endpoints: {
        authorizationEndpoint: 'https://idp/authorize',
        tokenEndpoint: 'https://idp/token',
        userinfoEndpoint: 'https://idp/userinfo',
      },
      scopes: ['openid'],
      fetch: vi.fn() as unknown as typeof globalThis.fetch,
    }),
    endpoints: {
      authorizationEndpoint: 'https://idp/authorize',
      tokenEndpoint: 'https://idp/token',
      userinfoEndpoint: 'https://idp/userinfo',
    },
    stateSigningSecret: 'sec',
    async fetchProfile() {
      return { sub: 's' }
    },
  }

  it('throws AUTH/MISCONFIGURED on a `javascript:` redirectUri', () => {
    expect(() => oauthProvider<MyProfile>({ ...baseOpts, redirectUri: 'javascript:alert(1)' })).toThrow(/MISCONFIGURED/)
  })

  it('throws on a redirectUri containing CR/LF (header injection)', () => {
    expect(() => oauthProvider<MyProfile>({ ...baseOpts, redirectUri: 'https://app/cb\r\nX-Inject: 1' })).toThrow(
      /MISCONFIGURED/,
    )
  })

  it('throws on a non-string redirectUri', () => {
    expect(() => oauthProvider<MyProfile>({ ...baseOpts, redirectUri: 42 as unknown as string })).toThrow(
      /MISCONFIGURED/,
    )
  })

  it('throws on an unparseable redirectUri', () => {
    expect(() => oauthProvider<MyProfile>({ ...baseOpts, redirectUri: 'not a url' })).toThrow(/MISCONFIGURED/)
  })

  it('accepts a normal https redirectUri', () => {
    expect(() => oauthProvider<MyProfile>({ ...baseOpts, redirectUri: 'https://app/cb' })).not.toThrow()
  })

  it('accepts a http redirectUri (some self-hosted setups still use it)', () => {
    expect(() => oauthProvider<MyProfile>({ ...baseOpts, redirectUri: 'http://localhost:3000/cb' })).not.toThrow()
  })
})
