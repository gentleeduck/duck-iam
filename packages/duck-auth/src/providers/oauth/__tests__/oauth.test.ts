import { createHash, createHmac, generateKeyPairSync } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { sha256 } from '~/core/crypto'
import { AuthEngine } from '~/core/engine'
import { Identities } from '~/core/identities'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { memoryDPoPNonceStore } from '~/core/transport/dpop-nonce.memory'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { afterOAuthBegin } from '~/test/oauth-browser'
import { apple } from '../apple/apple'
import { getUserinfoString, OAuthClient, oProvider } from '../core'
import { generatePkce } from '../core/pkce'
import { authBuildState, authVerifyState, signState } from '../core/state'
import { discord } from '../discord/discord'
import { github } from '../github/github'
import { google } from '../google/google'
import { linkedin } from '../linkedin/linkedin'
import { microsoft } from '../microsoft/microsoft'

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

/** The pair `begin` splits: the cookie stays in the browser, its digest rides in the state. */
const COOKIE = 'pre-auth-cookie-value'
const BINDING = sha256(COOKIE)
/** Under the name the provider sets outside production. */
const COOKIE_HEADER = `duck-oauth=${COOKIE}`

interface MyProfile extends Identities.ProfileMetadataBase {}

describe('oauth core - PKCE + state', () => {
  it('authGeneratePkce produces an S256 challenge derived from the verifier', () => {
    const { verifier, challenge, method } = generatePkce()
    expect(method).toBe('S256')
    expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(challenge).not.toBe(verifier)
  })

  it('signState / authVerifyState roundtrip', () => {
    const payload = authBuildState('oauth:google', { binding: BINDING })
    const state = signState(payload, 'secret')
    const back = authVerifyState(state, 'secret')
    expect(back?.providerId).toBe('oauth:google')
    expect(back?.nonce).toBe(payload.nonce)
  })

  it('authVerifyState rejects tampered signature', () => {
    const payload = authBuildState('oauth:google', { binding: BINDING })
    const state = signState(payload, 'secret')
    const tampered = `${state.slice(0, -3)}xxx`
    expect(authVerifyState(tampered, 'secret')).toBeNull()
  })

  it('authVerifyState rejects wrong secret', () => {
    const state = signState(authBuildState('oauth:google', { binding: BINDING }), 'secret-a')
    expect(authVerifyState(state, 'secret-b')).toBeNull()
  })

  describe('authVerifyState - SEC: payload validation', () => {
    const SECRET = 'secret'
    const base = authBuildState('oauth:google', { binding: BINDING })

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

    it('rejects payload whose nonce is a non-string (would weaken one-time-use guarantee)', () => {
      expect(authVerifyState(mintRawState({ ...base, nonce: null }, SECRET), SECRET)).toBeNull()
    })

    it('rejects payload whose returnTo is a non-string (open-redirect defense)', () => {
      expect(authVerifyState(mintRawState({ ...base, returnTo: { url: '/evil' } }, SECRET), SECRET)).toBeNull()
    })

    it('rejects payload whose returnTo is oversize (URL-bomb defense)', () => {
      // The state is HMAC-signed and carried in the oauth provider URL.
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
      expect(Reflect.apply(authVerifyState, undefined, [undefined, SECRET])).toBeNull()
      expect(Reflect.apply(authVerifyState, undefined, [42, SECRET])).toBeNull()
      expect(authVerifyState('', SECRET)).toBeNull()
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

describe('OAuthClient - SEC: token response validation', () => {
  function clientWithResponse(body: unknown, status = 200, raw = JSON.stringify(body)): OAuthClient {
    return new OAuthClient({
      clientId: 'cid',
      endpoints: {
        authorizationEndpoint: 'https://idp/authorize',
        tokenEndpoint: 'https://idp/token',
        userinfoEndpoint: 'https://idp/userinfo',
      },
      scopes: ['openid'],
      fetch: async () => new Response(raw, { status, headers: { 'content-type': 'application/json' } }),
    })
  }

  it('exchangeCode rejects non-object response (e.g. provider returns a JSON array)', async () => {
    const client = clientWithResponse(['not', 'an', 'object'])
    await expect(
      client.exchangeCode({ code: 'c', redirectUri: 'https://app/cb', codeVerifier: 'v' }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it('exchangeCode rejects response missing access_token', async () => {
    const client = clientWithResponse({ token_type: 'Bearer', expires_in: 3600 })
    await expect(
      client.exchangeCode({ code: 'c', redirectUri: 'https://app/cb', codeVerifier: 'v' }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it('exchangeCode rejects non-string access_token (would corrupt Bearer header downstream)', async () => {
    const client = clientWithResponse({ access_token: 42, token_type: 'Bearer' })
    await expect(
      client.exchangeCode({ code: 'c', redirectUri: 'https://app/cb', codeVerifier: 'v' }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it('exchangeCode rejects an expires_in that is not a finite number, which the host dates the token from', async () => {
    const exchange = (client: OAuthClient) =>
      client.exchangeCode({ code: 'c', redirectUri: 'https://app/cb', codeVerifier: 'v' })
    await expect(
      exchange(clientWithResponse({ access_token: 'at', token_type: 'Bearer', expires_in: '3600' })),
    ).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
    // JSON has no NaN, but `1e999` parses to Infinity.
    const infinite = '{ "access_token": "at", "token_type": "Bearer", "expires_in": 1e999 }'
    await expect(exchange(clientWithResponse(null, 200, infinite))).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
    await expect(
      exchange(clientWithResponse({ access_token: 'at', token_type: 'Bearer', expires_in: 3600 })),
    ).resolves.toMatchObject({
      expires_in: 3600,
    })
  })

  it('exchangeCode rejects non-string refresh_token', async () => {
    const client = clientWithResponse({ access_token: 'at', token_type: 'Bearer', refresh_token: { evil: true } })
    await expect(
      client.exchangeCode({ code: 'c', redirectUri: 'https://app/cb', codeVerifier: 'v' }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it('refresh rejects malformed response', async () => {
    const client = clientWithResponse({ token_type: 'Bearer' })
    await expect(client.refresh('rt')).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it('exchangeCode rejects invalid JSON body', async () => {
    const client = new OAuthClient({
      clientId: 'cid',
      endpoints: { authorizationEndpoint: 'https://idp/a', tokenEndpoint: 'https://idp/t' },
      scopes: ['openid'],
      fetch: async () => new Response('not json at all', { status: 200 }),
    })
    await expect(
      client.exchangeCode({ code: 'c', redirectUri: 'https://app/cb', codeVerifier: 'v' }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it('userinfo rejects non-object response body', async () => {
    const client = clientWithResponse('a string body')
    await expect(client.userinfo('at')).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it('authedJson refuses a non-http url before it reaches fetch', async () => {
    // The url is an argument rather than a validated endpoint, and a host reaches this method through
    // its own `fetchProfile`.
    const fetch = vi.fn<typeof globalThis.fetch>()
    const client = new OAuthClient({
      clientId: 'cid',
      endpoints: { authorizationEndpoint: 'https://idp/a', tokenEndpoint: 'https://idp/t' },
      fetch,
      scopes: ['openid'],
    })
    await expect(client.authedJson('file:///etc/passwd', 'at')).rejects.toMatchObject({
      code: 'AUTH_MISCONFIGURED',
    })
    expect(fetch).not.toHaveBeenCalled()
  })

  it('authedJson reports a non-2xx as a provider failure', async () => {
    const client = clientWithResponse({ message: 'Requires user:email' }, 403)
    await expect(client.authedJson('https://api.github.com/user/emails', 'at')).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
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

  it("keeps the endpoint's own query, as an Azure AD B2C policy endpoint carries one", async () => {
    const client = new OAuthClient({
      clientId: 'cid',
      endpoints: {
        authorizationEndpoint: 'https://idp.example.com/tenant/oauth2/v2.0/authorize?p=b2c_1_signin',
        tokenEndpoint: 'https://idp.example.com/tenant/oauth2/v2.0/token?p=b2c_1_signin',
      },
      scopes: ['openid'],
    })
    const u = new URL(await client.buildAuthorizeUrl({ redirectUri: 'https://app/cb', state: 's', codeChallenge: 'c' }))
    expect(u.pathname).toBe('/tenant/oauth2/v2.0/authorize')
    expect(u.searchParams.get('p')).toBe('b2c_1_signin')
    expect(u.searchParams.get('response_type')).toBe('code')
    expect(u.searchParams.get('state')).toBe('s')
  })

  it('answers its own value for a parameter the endpoint already names', async () => {
    const client = new OAuthClient({
      clientId: 'cid',
      endpoints: {
        authorizationEndpoint: 'https://idp.example.com/authorize?response_type=token&state=fixed',
        tokenEndpoint: 'https://idp.example.com/token',
      },
      scopes: ['openid'],
    })
    const u = new URL(await client.buildAuthorizeUrl({ redirectUri: 'https://app/cb', state: 's', codeChallenge: 'c' }))
    expect(u.searchParams.getAll('response_type')).toEqual(['code'])
    expect(u.searchParams.getAll('state')).toEqual(['s'])
  })
})

describe('oProvider - generic end-to-end (mocked IdP)', () => {
  function buildAuth(fakeIdp: typeof globalThis.fetch) {
    const adapter = new MemoryAdapter<MyProfile>()
    const auth = new AuthEngine<MyProfile>({
      baseUrl: 'https://app',
      transport: new CookieTransport({ name: 'duck-sid' }),
      stores: {
        identities: adapter.identities,
        sessions: adapter.sessions,
        credentials: adapter.credentials,
      },
      limiter: new MemoryLimiter({ max: 10, windowMs: 60_000 }),
      providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) })],
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
      oProvider<MyProfile>({
        providerId: 'fakeoidc',
        client,
        redirectUri: 'https://app/cb',
        stateSigningSecret: 'super-secret',
        nonceStore: memoryDPoPNonceStore(),
        async fetchProfile(tokens, c) {
          const info = await c.userinfo(tokens.access_token)
          const sub = getUserinfoString(info, 'sub') ?? ''
          return { email: getUserinfoString(info, 'email'), name: getUserinfoString(info, 'name'), sub }
        },
        profileToIdentityProfile: (p) => ({ username: p.email ?? '', email: p.email ?? '' }),
      }),
    )
    return { auth, adapter }
  }

  it('begin returns a redirect intent containing the authorize URL', async () => {
    const fetchImpl = vi.fn<typeof globalThis.fetch>()
    const { auth } = buildAuth(fetchImpl)
    const intents = await auth.flows.beginProvider('oauth:fakeoidc', {})
    const intent = intents.find((i) => i.type === 'redirect')
    expect(intent?.type).toBe('redirect')
    if (intent?.type === 'redirect') {
      const u = new URL(intent.url)
      expect(u.origin).toBe('https://idp')
      expect(u.searchParams.get('code_challenge_method')).toBe('S256')
      expect(u.searchParams.get('state')).toBeTruthy()
    }
  })

  it('begin also sets the cookie the callback has to come back with', async () => {
    const fetchImpl = vi.fn<typeof globalThis.fetch>()
    const { auth } = buildAuth(fetchImpl)
    const intents = await auth.flows.beginProvider('oauth:fakeoidc', {})
    const cookie = intents.find((i) => i.type === 'setCookie')

    expect(cookie).toMatchObject({
      name: 'duck-oauth',
      options: { httpOnly: true, path: '/', sameSite: 'lax', secure: false },
    })
    // The IdP sees the state, so the state carries the digest and the browser keeps the value.
    const { state, cookieHeader } = afterOAuthBegin(intents)
    expect(state).not.toContain(cookieHeader.split('=')[1] ?? '')
  })

  it('complete exchanges code, fetches userinfo, creates identity, returns startSession (auto-create branch)', async () => {
    const fetchImpl = vi.fn<typeof globalThis.fetch>(async (input) => {
      const url = String(input)
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
    })
    const { auth, adapter } = buildAuth(fetchImpl)

    // A real begin, whose cookie is the PKCE verifier.
    const { state, cookieHeader } = afterOAuthBegin(await auth.flows.beginProvider('oauth:fakeoidc', {}))

    const result = await auth.flows.signIn({
      providerId: 'oauth:fakeoidc',
      input: { code: 'authcode-abc', state, cookieHeader },
    })

    expect(result.session!.factors[0]?.method).toBe('oauth')
    // Spent with the code, so a recovered callback URL cannot be replayed in this browser.
    expect(result.intents).toContainEqual(
      expect.objectContaining({
        name: 'duck-oauth',
        options: expect.objectContaining({ maxAge: 0 }),
        type: 'clearCookie',
      }),
    )
    const identity = await adapter.identities.find({ email: 'new@x.com' })
    expect(identity).not.toBeNull()
    expect(identity?.providers.some((p) => p.providerId === 'oauth:fakeoidc' && p.providerSub === 'idp-user-1')).toBe(
      true,
    )
    // The IdP's refresh token is not stored: nothing could present it back, and a row per sign-in piled up.
    expect(await adapter.credentials.listByIdentity(identity?.id ?? '', null, {})).toEqual([])
  })

  it('keeps the PKCE verifier out of every URL, so a leaked callback cannot redeem its code', async () => {
    let tokenRequest = new URLSearchParams()
    const fetchImpl = vi.fn<typeof globalThis.fetch>(async (input, init) => {
      if (String(input).startsWith('https://idp/token')) {
        tokenRequest = new URLSearchParams(String(init?.body))
        return Response.json({ access_token: 'at-pkce', token_type: 'Bearer' })
      }
      return Response.json({ sub: 'idp-user-pkce', email: 'pkce@x.com' })
    })
    const { auth } = buildAuth(fetchImpl)
    const intents = await auth.flows.beginProvider('oauth:fakeoidc', {})
    const authorize = new URL(intents.find((i) => i.type === 'redirect' && 'url' in i)?.url ?? '')
    const { state, cookieHeader } = afterOAuthBegin(intents)
    await auth.flows.signIn({ providerId: 'oauth:fakeoidc', input: { code: 'authcode-pkce', state, cookieHeader } })

    const verifier = tokenRequest.get('code_verifier') ?? ''
    expect(createHash('sha256').update(verifier).digest('base64url')).toBe(authorize.searchParams.get('code_challenge'))
    // The IdP gets `state` in the authorize URL and hands it back beside `code` in the callback URL.
    expect(Buffer.from(state.split('.')[0] ?? '', 'base64url').toString('utf8')).not.toContain(verifier)
    expect(authorize.href).not.toContain(verifier)
  })

  it('complete refuses a callback that brings no cookie', async () => {
    // The login-CSRF shape: the attacker begins a flow, hands the victim the callback URL, and the
    // victim's browser finishes it. Their browser has no cookie from this begin, so it cannot.
    const fetchImpl = vi.fn<typeof globalThis.fetch>()
    const { auth } = buildAuth(fetchImpl)
    const { state } = afterOAuthBegin(await auth.flows.beginProvider('oauth:fakeoidc', {}))

    await expect(auth.flows.signIn({ input: { code: 'c', state }, providerId: 'oauth:fakeoidc' })).rejects.toThrow(
      /OAUTH_STATE_MISMATCH/,
    )
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it("complete refuses a callback carrying another browser's cookie", async () => {
    const fetchImpl = vi.fn<typeof globalThis.fetch>()
    const { auth } = buildAuth(fetchImpl)
    const attacker = afterOAuthBegin(await auth.flows.beginProvider('oauth:fakeoidc', {}))
    const victim = afterOAuthBegin(await auth.flows.beginProvider('oauth:fakeoidc', {}))

    await expect(
      auth.flows.signIn({
        input: { code: 'c', cookieHeader: victim.cookieHeader, state: attacker.state },
        providerId: 'oauth:fakeoidc',
      }),
    ).rejects.toThrow(/OAUTH_STATE_MISMATCH/)
  })

  it('complete refuses a cookie under the right name with the wrong value', async () => {
    const fetchImpl = vi.fn<typeof globalThis.fetch>()
    const { auth } = buildAuth(fetchImpl)
    const { state } = afterOAuthBegin(await auth.flows.beginProvider('oauth:fakeoidc', {}))

    await expect(
      auth.flows.signIn({
        input: { code: 'c', cookieHeader: 'duck-oauth=guessed', state },
        providerId: 'oauth:fakeoidc',
      }),
    ).rejects.toThrow(/OAUTH_STATE_MISMATCH/)
  })

  it('complete with tampered state surfaces AUTH/oauth/STATE_MISMATCH', async () => {
    const fetchImpl = vi.fn<typeof globalThis.fetch>()
    const { auth } = buildAuth(fetchImpl)
    await expect(
      auth.flows.signIn({
        providerId: 'oauth:fakeoidc',
        input: { code: 'authcode', state: 'tampered.state' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_OAUTH_STATE_MISMATCH' })
  })

  it('complete rejects oversize code (>2048 chars) BEFORE forwarding to IdP (outbound resource amplification defense)', async () => {
    const fetchImpl = vi.fn<typeof globalThis.fetch>()
    const { auth } = buildAuth(fetchImpl)
    const huge = 'x'.repeat(2049)
    await expect(
      auth.flows.signIn({
        providerId: 'oauth:fakeoidc',
        input: { code: huge, state: 'whatever' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
    // Library MUST not have fired any fetch - code rejected before exchange.
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('complete rejects empty code (defensive)', async () => {
    const fetchImpl = vi.fn<typeof globalThis.fetch>()
    const { auth } = buildAuth(fetchImpl)
    await expect(
      auth.flows.signIn({
        providerId: 'oauth:fakeoidc',
        input: { code: '', state: 'whatever' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('complete with state from a different provider surfaces AUTH/oauth/STATE_MISMATCH', async () => {
    const fetchImpl = vi.fn<typeof globalThis.fetch>()
    const { auth } = buildAuth(fetchImpl)
    // Forge a state signed correctly but for a different providerId.
    const payload = authBuildState('oauth:google', { binding: BINDING })
    const state = signState(payload, 'super-secret')
    await expect(
      auth.flows.signIn({
        providerId: 'oauth:fakeoidc',
        input: { code: 'x', state },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_OAUTH_STATE_MISMATCH' })
  })

  it('complete with second sign-in by same sub returns existing identity', async () => {
    const fetchImpl = vi.fn<typeof globalThis.fetch>(async (input) => {
      const url = String(input)
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
    })
    const { auth, adapter } = buildAuth(fetchImpl)

    const first = afterOAuthBegin(await auth.flows.beginProvider('oauth:fakeoidc', {}))
    await auth.flows.signIn({ providerId: 'oauth:fakeoidc', input: { code: 'c1', ...first } })
    const identitiesBefore = await adapter.identities.find({ email: 'a@x.com' })
    expect(identitiesBefore).not.toBeNull()

    const second = afterOAuthBegin(await auth.flows.beginProvider('oauth:fakeoidc', {}))
    const r2 = await auth.flows.signIn({ providerId: 'oauth:fakeoidc', input: { code: 'c2', ...second } })
    expect(r2.session!.identityId).toBe(identitiesBefore?.id)
  })

  it('refuses a replayed state dated ahead of this clock for as long as the state verifies', async () => {
    const idp = async (input: string | URL | Request): Promise<Response> =>
      String(input).startsWith('https://idp/token')
        ? Response.json({ access_token: 'at', token_type: 'Bearer' })
        : Response.json({ sub: 'skewed-1', email: 'skew@x.com' })
    const { auth } = buildAuth(idp)
    const T = Date.parse('2026-10-21T12:00:00Z')
    // Minted by a node whose clock runs five minutes ahead of this one.
    const ahead = mintRawState(
      { nonce: 'ahead', providerId: 'oauth:fakeoidc', binding: BINDING, iat: T + 5 * 60_000 },
      'super-secret',
    )
    const callback = (state: string) =>
      auth.flows.signIn({ providerId: 'oauth:fakeoidc', input: { code: 'c', state, cookieHeader: COOKIE_HEADER } })
    vi.useFakeTimers({ toFake: ['Date'] })
    try {
      vi.setSystemTime(T)
      await expect(callback(ahead)).resolves.toMatchObject({ session: expect.anything() })

      vi.setSystemTime(T + 10 * 60_000 + 1_000)
      await expect(callback(ahead)).rejects.toMatchObject({ code: 'AUTH_OAUTH_NONCE_REPLAY' })
      const fresh = mintRawState(
        { nonce: 'fresh', providerId: 'oauth:fakeoidc', binding: BINDING, iat: T + 10 * 60_000 },
        'super-secret',
      )
      await expect(callback(fresh)).resolves.toMatchObject({ session: expect.anything() })

      vi.setSystemTime(T + 15 * 60_000 + 1_000)
      await expect(callback(ahead)).rejects.toMatchObject({ code: 'AUTH_OAUTH_STATE_MISMATCH' })
    } finally {
      vi.useRealTimers()
    }
  })
})

describe('oProvider - an IdP that is down or never answers', () => {
  type Mode = 'up' | 'refused' | 'silent' | 'no-sub'

  /** A working IdP, or one failing as `mode` says. A silent endpoint settles only when the request is aborted. */
  function idp(state: { mode: Mode; revocation: 'up' | 'silent' }): typeof globalThis.fetch {
    return async (input, init) => {
      const url = String(input)
      const silent = () =>
        new Promise<Response>((_, reject) => init?.signal?.addEventListener('abort', () => reject(init.signal?.reason)))
      if (url.startsWith('https://idp/revoke')) return state.revocation === 'silent' ? silent() : new Response(null)
      if (state.mode === 'refused') throw new TypeError('fetch failed')
      if (state.mode === 'silent') return silent()
      if (url.startsWith('https://idp/token')) return Response.json({ access_token: 'at', token_type: 'Bearer' })
      return Response.json(state.mode === 'no-sub' ? {} : { sub: 'down-1', email: 'down@x.com' })
    }
  }

  function build(fetch: typeof globalThis.fetch, timeoutMs: number) {
    const adapter = new MemoryAdapter<MyProfile>()
    const auth = new AuthEngine<MyProfile>({
      baseUrl: 'https://app',
      transport: new CookieTransport({ name: 'duck-sid' }),
      stores: { identities: adapter.identities, sessions: adapter.sessions, credentials: adapter.credentials },
    })
    const client = new OAuthClient({
      clientId: 'cid',
      clientSecret: 'csec',
      endpoints: {
        authorizationEndpoint: 'https://idp/authorize',
        tokenEndpoint: 'https://idp/token',
        userinfoEndpoint: 'https://idp/userinfo',
        revocationEndpoint: 'https://idp/revoke',
      },
      scopes: ['openid'],
      fetch,
      timeoutMs,
    })
    auth.providers.register(
      oProvider<MyProfile>({
        providerId: 'fakeoidc',
        client,
        redirectUri: 'https://app/cb',
        stateSigningSecret: 'super-secret',
        nonceStore: memoryDPoPNonceStore(),
        async fetchProfile(tokens, c) {
          const info = await c.userinfo(tokens.access_token)
          return { sub: getUserinfoString(info, 'sub') ?? '', email: getUserinfoString(info, 'email') }
        },
        profileToIdentityProfile: (p) => ({ username: p.email ?? '', email: p.email ?? '' }),
      }),
    )
    return async () => {
      const begun = afterOAuthBegin(await auth.flows.beginProvider('oauth:fakeoidc', {}))
      return auth.flows.signIn({ providerId: 'oauth:fakeoidc', input: { code: 'c', ...begun } })
    }
  }

  it('fails a sign-in whose IdP refuses the connection as AUTH_PROVIDER_FAILED, which a callback catches', async () => {
    const state: { mode: Mode; revocation: 'up' | 'silent' } = { mode: 'refused', revocation: 'up' }
    const signIn = build(idp(state), 1_000)
    await expect(signIn()).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
      meta: { detail: expect.stringContaining('token endpoint unreachable') },
    })
    state.mode = 'up'
    await expect(signIn()).resolves.toMatchObject({ session: expect.anything() })
  })

  it('gives up on an IdP that never answers after timeoutMs', async () => {
    const state: { mode: Mode; revocation: 'up' | 'silent' } = { mode: 'silent', revocation: 'up' }
    const signIn = build(idp(state), 100)
    await expect(signIn()).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
      meta: { detail: expect.stringContaining('token endpoint unreachable') },
    })
    state.mode = 'up'
    await expect(signIn()).resolves.toMatchObject({ session: expect.anything() })
  }, 3_000)

  it('answers a refusal after the exchange without waiting on a revocation endpoint that never answers', async () => {
    const state: { mode: Mode; revocation: 'up' | 'silent' } = { mode: 'no-sub', revocation: 'silent' }
    const signIn = build(idp(state), 100)
    const missingSub = { code: 'AUTH_PROVIDER_FAILED', meta: { detail: 'oauth profile missing sub' } }
    await expect(signIn()).rejects.toMatchObject(missingSub)
    state.revocation = 'up'
    await expect(signIn()).rejects.toMatchObject(missingSub)
  }, 3_000)

  it('refuses a timeoutMs no timer can hold', () => {
    const client = (timeoutMs: number) =>
      new OAuthClient({
        clientId: 'cid',
        endpoints: { authorizationEndpoint: 'https://idp/a', tokenEndpoint: 'https://idp/t' },
        scopes: [],
        timeoutMs,
      })
    for (const timeoutMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 2_147_483_648]) {
      expect(() => client(timeoutMs)).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
    }
    expect(() => client(1)).not.toThrow()
    expect(() => client(2_147_483_647)).not.toThrow()
  })

  it('is honoured by every shipped provider', async () => {
    // Answers a 400 after 100ms, so a 50ms timeout gives up first and a 1s one hears the refusal.
    const slow: typeof globalThis.fetch = (_input, init) =>
      new Promise((resolve, reject) => {
        const timer = setTimeout(() => resolve(new Response('no', { status: 400 })), 100)
        init?.signal?.addEventListener('abort', () => {
          clearTimeout(timer)
          reject(init.signal?.reason)
        })
      })
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const shipped = (timeoutMs: number) => {
      const common = {
        clientId: 'cid',
        fetch: slow,
        redirectUri: 'https://app/cb',
        stateSigningSecret: 'super-secret',
        nonceStore: memoryDPoPNonceStore(),
        timeoutMs,
      }
      return [
        google<MyProfile>({ ...common, clientSecret: 'csec' }),
        github<MyProfile>({ ...common, clientSecret: 'csec' }),
        discord<MyProfile>({ ...common, clientSecret: 'csec' }),
        linkedin<MyProfile>({ ...common, clientSecret: 'csec' }),
        microsoft<MyProfile>({ ...common, clientSecret: 'csec' }),
        apple<MyProfile>({
          ...common,
          teamId: 'TEAM123456',
          keyId: 'KEYID12345',
          privateKey: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
        }),
      ]
    }
    const detailOf = async (provider: ReturnType<typeof shipped>[number]) => {
      const adapter = new MemoryAdapter<MyProfile>()
      const auth = new AuthEngine<MyProfile>({
        baseUrl: 'https://app',
        providers: [provider],
        stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
        transport: new CookieTransport({ name: 'duck-sid' }),
      })
      const begun = afterOAuthBegin(await auth.flows.beginProvider(provider.id, {}))
      return auth.flows.signIn({ providerId: provider.id, input: { code: 'c', ...begun } }).then(
        () => 'signed in',
        (err: { meta?: { detail?: string } }) => err.meta?.detail ?? 'no detail',
      )
    }
    for (const provider of shipped(50)) {
      expect([provider.id, await detailOf(provider)]).toEqual([provider.id, expect.stringContaining('unreachable')])
    }
    for (const provider of shipped(1_000)) {
      expect([provider.id, await detailOf(provider)]).toEqual([provider.id, expect.stringContaining('returned 400')])
    }
  })
})

describe('oProvider - the state cookie and the nonce store follow NODE_ENV', () => {
  const client = new OAuthClient({
    clientId: 'cid',
    clientSecret: 'csec',
    endpoints: { authorizationEndpoint: 'https://idp/authorize', tokenEndpoint: 'https://idp/token' },
    scopes: ['openid'],
  })
  const opts = {
    providerId: 'fakeoidc',
    client,
    redirectUri: 'https://app/cb',
    stateSigningSecret: 'super-secret',
    async fetchProfile() {
      return { sub: 's' }
    },
  }
  // Not the memory store, which production refuses on its own.
  const nonceStore = { recordSeen: async () => true }

  async function stateCookie(extra: Partial<Parameters<typeof oProvider<MyProfile>>[0]> = {}) {
    const adapter = new MemoryAdapter<MyProfile>()
    const auth = new AuthEngine<MyProfile>({
      baseUrl: 'https://app',
      transport: new CookieTransport({ name: 'duck-sid' }),
      stores: { identities: adapter.identities, sessions: adapter.sessions, credentials: adapter.credentials },
      providers: [oProvider<MyProfile>({ ...opts, nonceStore, ...extra })],
    })
    return (await auth.flows.beginProvider('oauth:fakeoidc', {})).find((i) => i.type === 'setCookie')
  }

  it('sets the state cookie Secure under the __Host- prefix in production', async () => {
    vi.stubEnv('NODE_ENV', 'production')
    expect(await stateCookie()).toMatchObject({
      name: '__Host-duck-oauth',
      options: { httpOnly: true, path: '/', sameSite: 'lax', secure: true },
    })
  })

  // Over plain http, which is how a dev server runs, a browser drops a Secure cookie and any `__Host-` one.
  it.each(['development', 'test'])('drops Secure and the __Host- prefix under NODE_ENV=%s', async (env) => {
    vi.stubEnv('NODE_ENV', env)
    expect(await stateCookie()).toMatchObject({ name: 'duck-oauth', options: { sameSite: 'lax', secure: false } })
  })

  // `form_post` makes the callback a cross-site POST, so the cookie is SameSite=None, which needs Secure.
  it('keeps a form_post cookie Secure outside production', async () => {
    vi.stubEnv('NODE_ENV', 'development')
    expect(await stateCookie({ responseMode: 'form_post' })).toMatchObject({
      name: '__Host-duck-oauth',
      options: { sameSite: 'none', secure: true },
    })
  })

  it.each(['development', 'production'])('refuses a __Host- name with a domain under NODE_ENV=%s', (env) => {
    vi.stubEnv('NODE_ENV', env)
    expect(() =>
      oProvider<MyProfile>({ ...opts, nonceStore, stateCookie: { domain: 'app', name: '__Host-duck-oauth' } }),
    ).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })

  // A state nothing burns is a callback URL that completes again for the rest of its ten minutes.
  it('refuses a provider with no nonce store in production', () => {
    vi.stubEnv('NODE_ENV', 'production')
    expect(() => oProvider<MyProfile>(opts)).toThrow(
      expect.objectContaining({
        code: 'AUTH_MISCONFIGURED',
        meta: { detail: 'oauth requires `nonceStore` in production (provider fakeoidc)' },
      }),
    )
  })

  it.each(['development', 'test'])('accepts a provider with no nonce store under NODE_ENV=%s', (env) => {
    vi.stubEnv('NODE_ENV', env)
    expect(() => oProvider<MyProfile>(opts)).not.toThrow()
  })
})

describe('oProvider - redirectUri construction guard', () => {
  const baseOpts = {
    providerId: 'fakeoidc',
    client: new OAuthClient({
      clientId: 'cid',
      clientSecret: 'csec',
      endpoints: {
        authorizationEndpoint: 'https://idp/authorize',
        tokenEndpoint: 'https://idp/token',
        userinfoEndpoint: 'https://idp/userinfo',
      },
      scopes: ['openid'],
      fetch: vi.fn<typeof globalThis.fetch>(),
    }),
    stateSigningSecret: 'sec',
    async fetchProfile() {
      return { sub: 's' }
    },
  }

  it('throws AUTH_MISCONFIGURED on a `javascript:` redirectUri', () => {
    expect(() => oProvider<MyProfile>({ ...baseOpts, redirectUri: 'javascript:alert(1)' })).toThrow(/MISCONFIGURED/)
  })

  it('refuses a __Host- state cookie the browser would silently drop', () => {
    const redirectUri = 'https://app/callback'
    expect(() =>
      oProvider<MyProfile>({ ...baseOpts, redirectUri, stateCookie: { domain: 'app', name: '__Host-duck-oauth' } }),
    ).toThrow(/MISCONFIGURED/)
    // A domain with no name asked for is not a conflict: the default drops the prefix for it.
    expect(() => oProvider<MyProfile>({ ...baseOpts, redirectUri, stateCookie: { domain: 'app' } })).not.toThrow()
  })

  it('throws on a redirectUri containing CR/LF (header injection)', () => {
    expect(() => oProvider<MyProfile>({ ...baseOpts, redirectUri: 'https://app/cb\r\nX-Inject: 1' })).toThrow(
      /MISCONFIGURED/,
    )
  })

  it('throws on a non-string redirectUri', () => {
    expect(() => Reflect.apply(oProvider, undefined, [{ ...baseOpts, redirectUri: 42 }])).toThrow(/MISCONFIGURED/)
  })

  it('throws on an unparseable redirectUri', () => {
    expect(() => oProvider<MyProfile>({ ...baseOpts, redirectUri: 'not a url' })).toThrow(/MISCONFIGURED/)
  })

  it('accepts a normal https redirectUri', () => {
    expect(() => oProvider<MyProfile>({ ...baseOpts, redirectUri: 'https://app/cb' })).not.toThrow()
  })

  it('accepts a http redirectUri (some self-hosted setups still use it)', () => {
    expect(() => oProvider<MyProfile>({ ...baseOpts, redirectUri: 'http://localhost:3000/cb' })).not.toThrow()
  })
})
