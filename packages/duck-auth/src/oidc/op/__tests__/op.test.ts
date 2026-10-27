import { createHmac } from 'node:crypto'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import type { Identities } from '~/core'
import { sha256 } from '~/core/crypto'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { passwords } from '~/providers/passwords'
import { ScryptHasher } from '~/providers/passwords/hashers/scrypt'
import { createOidcOP, type OidcOpRoot } from '../index'
import type { OidcOP } from '../types'

function isoauthError(v: OidcOP.OauthError | object): v is OidcOP.OauthError {
  return 'error' in v && typeof v.error === 'string' && !('sub' in v)
}

interface ProfileShape extends Identities.ProfileMetadataBase {
  name?: string
  email_verified?: boolean
}

function buildAuth() {
  const adapter = new MemoryAdapter<ProfileShape>()
  return new AuthEngine<ProfileShape>({
    baseUrl: 'http://localhost:8787',
    stores: { identities: adapter.identities, credentials: adapter.credentials, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid' }),
    providers: [passwords({ hasher: new ScryptHasher() })],
  })
}

function buildOp(auth: ReturnType<typeof buildAuth>): OidcOpRoot<ProfileShape> {
  const secret = 'dev-hmac-secret'
  return createOidcOP<ProfileShape>({
    auth,
    config: {
      issuer: 'http://localhost:8787/auth',
      supportedScopes: ['openid', 'profile', 'email', 'offline_access'],
    },
    signIdToken: (payload) => {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
      const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
      const sig = createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url')
      return `${header}.${body}.${sig}`
    },
  })
}

describe('AuthOidcOP - the issuer scheme follows NODE_ENV', () => {
  const none = async () => null
  const done = async () => {}
  /** Production refuses the in-memory stores, so every one is passed and the issuer is all that is judged. */
  const stores = {
    accessTokens: { findByHash: none, insert: done, revokeByHash: done, revokeFamily: done },
    clients: { findById: none, insert: done },
    codes: { consume: none, insert: done },
    consents: { find: none, upsert: done },
    refreshTokens: { consume: none, findByHash: none, insert: done, revokeFamily: done },
  }
  const op = (issuer: string) =>
    createOidcOP<ProfileShape>({
      auth: buildAuth(),
      config: { issuer, supportedScopes: ['openid'] },
      signIdToken: () => 'unsigned',
      stores,
    })

  it.each(['production', undefined])('refuses an http issuer with NODE_ENV=%s', (env) => {
    vi.stubEnv('NODE_ENV', env)
    expect(() => op('http://localhost:8787/auth')).toThrow(
      expect.objectContaining({
        code: 'AUTH_MISCONFIGURED',
        meta: { detail: 'AuthOidcOP: issuer must use HTTPS (http:); plain http is admitted only outside production' },
      }),
    )
    expect(op('https://op.example.com/auth').issuer).toBe('https://op.example.com/auth')
  })

  it.each(['development', 'test'])('admits an http issuer with NODE_ENV=%s, and no other scheme', (env) => {
    vi.stubEnv('NODE_ENV', env)
    expect(op('http://localhost:8787/auth').issuer).toBe('http://localhost:8787/auth')
    expect(() => op('ftp://localhost:8787/auth')).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })
})

describe('AuthOidcOP - the issuer loses its trailing slashes in linear time', () => {
  it('trims them, and a long run of slashes inside the path costs no backtracking', () => {
    const auth = buildAuth()
    const op = (issuer: string) =>
      createOidcOP<ProfileShape>({
        auth,
        config: { issuer, supportedScopes: ['openid'] },
        signIdToken: () => 'unsigned',
      })
    expect(op('https://op.example.com/auth///').issuer).toBe('https://op.example.com/auth')
    const issuer = `https://op.example.com/${'/'.repeat(100_000)}x`
    const started = performance.now()
    expect(op(issuer).issuer).toBe(issuer)
    expect(performance.now() - started).toBeLessThan(250)
  })
})

function decodeJwt(token: string): Record<string, unknown> {
  const parts = token.split('.')
  if (parts.length !== 3) throw new Error('not a JWT')
  const body = parts[1]
  if (typeof body !== 'string') throw new Error('JWT body missing')
  const decoded = Buffer.from(body, 'base64url').toString('utf8')
  const obj: unknown = JSON.parse(decoded)
  if (typeof obj !== 'object' || obj === null) throw new Error('JWT body not an object')
  return obj as Record<string, unknown>
}

function pkceVerifierAndChallenge(): { verifier: string; challenge: string } {
  const verifier = 'a'.repeat(64)
  const hex = sha256(verifier)
  const challenge = Buffer.from(hex, 'hex').toString('base64url')
  return { verifier, challenge }
}

describe('AuthOidcOpRoot.registerClient', () => {
  it('returns a generated client_secret for confidential clients', async () => {
    const op = buildOp(buildAuth())
    const out = await op.registerClient({
      client_id: 'web-app',
      redirect_uris: ['https://app.example.com/callback'],
      token_endpoint_auth_method: 'client_secret_basic',
    })
    expect(out.client_secret).not.toBeNull()
    expect(out.client_secret?.length).toBeGreaterThan(20)
  })

  it('returns null secret for public clients', async () => {
    const op = buildOp(buildAuth())
    const out = await op.registerClient({
      client_id: 'spa',
      redirect_uris: ['https://app.example.com/cb'],
      token_endpoint_auth_method: 'none',
    })
    expect(out.client_secret).toBeNull()
  })

  it('rejects non-loopback http redirect_uris', async () => {
    const op = buildOp(buildAuth())
    await expect(
      op.registerClient({
        client_id: 'bad',
        redirect_uris: ['http://attacker.example.com/cb'],
      }),
    ).rejects.toThrow(
      expect.objectContaining({
        code: 'AUTH_INVALID_PARAMETERS',
        meta: { detail: expect.stringContaining('non-loopback http redirect_uri rejected') },
      }),
    )
  })

  it('allows http://localhost for dev', async () => {
    const op = buildOp(buildAuth())
    const out = await op.registerClient({
      client_id: 'dev',
      redirect_uris: ['http://localhost:3000/cb'],
      token_endpoint_auth_method: 'none',
    })
    expect(out.client_id).toBe('dev')
  })

  it('allows http://[::1] (IPv6 loopback, RFC 8252)', async () => {
    const op = buildOp(buildAuth())
    const out = await op.registerClient({
      client_id: 'dev-v6',
      redirect_uris: ['http://[::1]:3000/cb'],
      token_endpoint_auth_method: 'none',
    })
    expect(out.client_id).toBe('dev-v6')
  })

  it('rejects non-loopback http (e.g. http://example.com)', async () => {
    const op = buildOp(buildAuth())
    await expect(
      op.registerClient({
        client_id: 'bad',
        redirect_uris: ['http://example.com/cb'],
        token_endpoint_auth_method: 'none',
      }),
    ).rejects.toThrow(
      expect.objectContaining({
        code: 'AUTH_INVALID_PARAMETERS',
        meta: { detail: expect.stringContaining('non-loopback http redirect_uri rejected') },
      }),
    )
  })
})

describe('AuthOidcOpRoot.authorize gate', () => {
  it('rejects unknown client without redirecting', async () => {
    const op = buildOp(buildAuth())
    const result = await op.authorize(
      {
        client_id: 'unknown',
        redirect_uri: 'http://localhost/cb',
        response_type: 'code',
        scope: 'openid',
      },
      { headers: new Headers() },
    )
    expect(result.kind).toBe('error')
    if (result.kind === 'error') expect(result.body.error).toBe('invalid_client')
  })

  it('rejects mismatched redirect_uri without redirecting', async () => {
    const op = buildOp(buildAuth())
    await op.registerClient({
      client_id: 'app',
      redirect_uris: ['https://app.example.com/cb'],
      token_endpoint_auth_method: 'none',
    })
    const result = await op.authorize(
      {
        client_id: 'app',
        redirect_uri: 'https://evil.example.com/cb',
        response_type: 'code',
        scope: 'openid',
      },
      { headers: new Headers() },
    )
    expect(result.kind).toBe('error')
    if (result.kind === 'error') expect(result.body.error).toBe('invalid_request')
  })

  it('requires PKCE for public clients', async () => {
    const op = buildOp(buildAuth())
    await op.registerClient({
      client_id: 'spa',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'none',
    })
    const result = await op.authorize(
      {
        client_id: 'spa',
        redirect_uri: 'http://localhost/cb',
        response_type: 'code',
        scope: 'openid',
      },
      { headers: new Headers() },
    )
    expect(result.kind).toBe('error')
    if (result.kind === 'error') {
      expect(result.body.error).toBe('invalid_request')
      expect(result.body.error_description).toMatch(/PKCE/)
    }
  })

  it('rejects unsupported response_type with redirected error', async () => {
    const op = buildOp(buildAuth())
    await op.registerClient({
      client_id: 'app',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'none',
    })
    const result = await op.authorize(
      {
        client_id: 'app',
        redirect_uri: 'http://localhost/cb',
        response_type: 'token',
        scope: 'openid',
      },
      { headers: new Headers() },
    )
    expect(result.kind).toBe('error')
    if (result.kind === 'error') {
      expect(result.body.error).toBe('unsupported_response_type')
      expect(result.status).toBe(302)
    }
  })

  it('rejects oversize scope (DoS cap)', async () => {
    const op = buildOp(buildAuth())
    await op.registerClient({
      client_id: 'spa',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'none',
    })
    const { challenge } = pkceVerifierAndChallenge()
    const huge = 'openid '.repeat(2000)
    const result = await op.authorize(
      {
        client_id: 'spa',
        redirect_uri: 'http://localhost/cb',
        response_type: 'code',
        scope: huge,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      },
      { headers: new Headers() },
    )
    expect(result.kind).toBe('error')
    if (result.kind === 'error') {
      expect(result.body.error).toBe('invalid_scope')
      expect(result.body.error_description).toMatch(/too long|too many/)
    }
  })

  it('rejects scope with too many tokens (DoS cap)', async () => {
    const op = buildOp(buildAuth())
    await op.registerClient({
      client_id: 'spa',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'none',
    })
    const { challenge } = pkceVerifierAndChallenge()
    const many = Array.from({ length: 100 }, (_, i) => `s${i}`).join(' ')
    const result = await op.authorize(
      {
        client_id: 'spa',
        redirect_uri: 'http://localhost/cb',
        response_type: 'code',
        scope: many,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      },
      { headers: new Headers() },
    )
    expect(result.kind).toBe('error')
    if (result.kind === 'error') {
      expect(result.body.error).toBe('invalid_scope')
      expect(result.body.error_description).toMatch(/too many/)
    }
  })

  it('rejects request missing openid scope', async () => {
    const op = buildOp(buildAuth())
    await op.registerClient({
      client_id: 'spa',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'none',
    })
    const { challenge } = pkceVerifierAndChallenge()
    const result = await op.authorize(
      {
        client_id: 'spa',
        redirect_uri: 'http://localhost/cb',
        response_type: 'code',
        scope: 'profile',
        code_challenge: challenge,
        code_challenge_method: 'S256',
      },
      { headers: new Headers() },
    )
    expect(result.kind).toBe('error')
    if (result.kind === 'error') expect(result.body.error).toBe('invalid_scope')
  })

  it('returns login_required when no session and prompt!=none', async () => {
    const op = buildOp(buildAuth())
    await op.registerClient({
      client_id: 'spa',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'none',
    })
    const { challenge } = pkceVerifierAndChallenge()
    const result = await op.authorize(
      {
        client_id: 'spa',
        redirect_uri: 'http://localhost/cb',
        response_type: 'code',
        scope: 'openid',
        code_challenge: challenge,
        code_challenge_method: 'S256',
      },
      { headers: new Headers() },
    )
    expect(result.kind).toBe('login_required')
  })

  it('errors with login_required when no session and prompt=none', async () => {
    const op = buildOp(buildAuth())
    await op.registerClient({
      client_id: 'spa',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'none',
    })
    const { challenge } = pkceVerifierAndChallenge()
    const result = await op.authorize(
      {
        client_id: 'spa',
        redirect_uri: 'http://localhost/cb',
        response_type: 'code',
        scope: 'openid',
        prompt: 'none',
        code_challenge: challenge,
        code_challenge_method: 'S256',
      },
      { headers: new Headers() },
    )
    expect(result.kind).toBe('error')
    if (result.kind === 'error') expect(result.body.error).toBe('login_required')
  })
})

describe('AuthOidcOpRoot end-to-end code flow', () => {
  let auth: ReturnType<typeof buildAuth>
  let op: OidcOpRoot<ProfileShape>

  beforeEach(() => {
    auth = buildAuth()
    op = buildOp(auth)
  })

  it('mints a code -> exchanges for tokens -> userinfo returns scoped claims', async () => {
    await op.registerClient({
      client_id: 'spa',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'none',
      scope: ['openid', 'profile', 'email', 'offline_access'],
    })
    const identity = await auth.identities.create({
      emailVerified: true,
      profile: { email: 'u@x.com', name: 'Ursula', username: 'u' },
    })
    const { verifier, challenge } = pkceVerifierAndChallenge()
    const completed = await op.completeConsent({
      client_id: 'spa',
      identity,
      redirect_uri: 'http://localhost/cb',
      scope: ['openid', 'profile', 'email', 'offline_access'],
      state: 'xyz',
      nonce: 'n-abc',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      sid: 'sess-1',
      tenant_id: null,
    })
    expect(completed.kind).toBe('redirect')
    if (completed.kind !== 'redirect') throw new Error('expected redirect')
    const cbUrl = new URL(completed.url)
    expect(cbUrl.searchParams.get('state')).toBe('xyz')
    const code = cbUrl.searchParams.get('code')
    expect(code).not.toBeNull()
    if (code === null) throw new Error('missing code')

    const tok = await op.token(
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://localhost/cb',
        client_id: 'spa',
        code_verifier: verifier,
      },
      new Headers(),
    )
    expect('error' in tok).toBe(false)
    if ('error' in tok) throw new Error(tok.error)
    expect(tok.token_type).toBe('Bearer')
    expect(tok.refresh_token).toBeTruthy()
    expect(tok.id_token).toBeTruthy()
    const idPayload = decodeJwt(tok.id_token ?? '')
    expect(idPayload.sub).toBe(identity.id)
    expect(idPayload.aud).toBe('spa')
    expect(idPayload.nonce).toBe('n-abc')
    expect(idPayload.iss).toBe('http://localhost:8787/auth')

    const ui = await op.userinfo(new Headers({ authorization: `Bearer ${tok.access_token}` }))
    if (isoauthError(ui)) throw new Error(ui.error)
    expect(ui.sub).toBe(identity.id)
    expect(ui.name).toBe('Ursula')
    expect(ui.email).toBe('u@x.com')
    expect(ui.email_verified).toBe(true)
  })

  it('rejects authorization_code with a wrong PKCE verifier', async () => {
    await op.registerClient({
      client_id: 'spa',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'none',
      scope: ['openid'],
    })
    const identity = await auth.identities.create({ profile: { email: 'u@x.com', username: 'u' } })
    const { challenge } = pkceVerifierAndChallenge()
    const completed = await op.completeConsent({
      client_id: 'spa',
      identity,
      redirect_uri: 'http://localhost/cb',
      scope: ['openid'],
      code_challenge: challenge,
      code_challenge_method: 'S256',
      sid: 'sess-2',
      tenant_id: null,
    })
    if (completed.kind !== 'redirect') throw new Error('expected redirect')
    const code = new URL(completed.url).searchParams.get('code')
    if (code === null) throw new Error('missing code')
    const tok = await op.token(
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://localhost/cb',
        client_id: 'spa',
        code_verifier: 'wrong-verifier-1234567890123456789012345678901234',
      },
      new Headers(),
    )
    expect('error' in tok).toBe(true)
    if ('error' in tok) expect(tok.error).toBe('invalid_grant')
  })

  it('rejects code replay (codes are single-use)', async () => {
    await op.registerClient({
      client_id: 'spa',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'none',
      scope: ['openid'],
    })
    const identity = await auth.identities.create({ profile: { email: 'u@x.com', username: 'u' } })
    const { verifier, challenge } = pkceVerifierAndChallenge()
    const completed = await op.completeConsent({
      client_id: 'spa',
      identity,
      redirect_uri: 'http://localhost/cb',
      scope: ['openid'],
      code_challenge: challenge,
      code_challenge_method: 'S256',
      sid: 'sess-3',
      tenant_id: null,
    })
    if (completed.kind !== 'redirect') throw new Error('expected redirect')
    const code = new URL(completed.url).searchParams.get('code')
    if (code === null) throw new Error('missing code')
    await op.token(
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://localhost/cb',
        client_id: 'spa',
        code_verifier: verifier,
      },
      new Headers(),
    )
    const replay = await op.token(
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://localhost/cb',
        client_id: 'spa',
        code_verifier: verifier,
      },
      new Headers(),
    )
    expect('error' in replay).toBe(true)
    if ('error' in replay) expect(replay.error).toBe('invalid_grant')
  })

  it('refresh_token rotation works; reuse triggers family revoke', async () => {
    await op.registerClient({
      client_id: 'spa',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'none',
      scope: ['openid', 'offline_access'],
    })
    const identity = await auth.identities.create({ profile: { email: 'u@x.com', username: 'u' } })
    const { verifier, challenge } = pkceVerifierAndChallenge()
    const completed = await op.completeConsent({
      client_id: 'spa',
      identity,
      redirect_uri: 'http://localhost/cb',
      scope: ['openid', 'offline_access'],
      code_challenge: challenge,
      code_challenge_method: 'S256',
      sid: 'sess-4',
      tenant_id: null,
    })
    if (completed.kind !== 'redirect') throw new Error('expected redirect')
    const code = new URL(completed.url).searchParams.get('code')
    if (code === null) throw new Error('missing code')
    const first = await op.token(
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://localhost/cb',
        client_id: 'spa',
        code_verifier: verifier,
      },
      new Headers(),
    )
    if ('error' in first) throw new Error(first.error)
    const rt1 = first.refresh_token
    if (!rt1) throw new Error('refresh missing')
    const refreshed = await op.token(
      {
        grant_type: 'refresh_token',
        refresh_token: rt1,
        client_id: 'spa',
      },
      new Headers(),
    )
    if ('error' in refreshed) throw new Error(refreshed.error)
    expect(refreshed.refresh_token).toBeTruthy()
    expect(refreshed.refresh_token).not.toBe(rt1)
    // Reuse old rt1: should fail AND revoke the new one.
    const reuse = await op.token(
      {
        grant_type: 'refresh_token',
        refresh_token: rt1,
        client_id: 'spa',
      },
      new Headers(),
    )
    expect('error' in reuse).toBe(true)
    if ('error' in reuse) expect(reuse.error).toBe('invalid_grant')
    // After family revoke, the rotated rt should also be dead.
    const second = await op.token(
      {
        grant_type: 'refresh_token',
        refresh_token: refreshed.refresh_token ?? '',
        client_id: 'spa',
      },
      new Headers(),
    )
    expect('error' in second).toBe(true)
  })

  it('introspect: confidential client gets active=true for live access token', async () => {
    const { client_secret } = await op.registerClient({
      client_id: 'resource',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'client_secret_basic',
      scope: ['openid'],
    })
    if (!client_secret) throw new Error('expected secret')
    await op.registerClient({
      client_id: 'spa',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'none',
      scope: ['openid'],
    })
    const identity = await auth.identities.create({ profile: { email: 'u@x.com', username: 'u' } })
    const { verifier, challenge } = pkceVerifierAndChallenge()
    const completed = await op.completeConsent({
      client_id: 'spa',
      identity,
      redirect_uri: 'http://localhost/cb',
      scope: ['openid'],
      code_challenge: challenge,
      code_challenge_method: 'S256',
      sid: 'sess-5',
      tenant_id: null,
    })
    if (completed.kind !== 'redirect') throw new Error('expected redirect')
    const code = new URL(completed.url).searchParams.get('code')
    if (code === null) throw new Error('missing code')
    const tok = await op.token(
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://localhost/cb',
        client_id: 'spa',
        code_verifier: verifier,
      },
      new Headers(),
    )
    if ('error' in tok) throw new Error(tok.error)
    const basic = Buffer.from(`resource:${client_secret}`).toString('base64')
    const result = await op.introspect(
      { token: tok.access_token, token_type_hint: 'access_token' },
      new Headers({ authorization: `Basic ${basic}` }),
    )
    expect(result.active).toBe(true)
    expect(result.sub).toBe(identity.id)
    expect(result.client_id).toBe('spa')
  })

  it('revoke: kills an active access token', async () => {
    const { client_secret } = await op.registerClient({
      client_id: 'resource',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'client_secret_basic',
      scope: ['openid'],
    })
    if (!client_secret) throw new Error('expected secret')
    await op.registerClient({
      client_id: 'spa',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'none',
      scope: ['openid'],
    })
    const identity = await auth.identities.create({ profile: { email: 'u@x.com', username: 'u' } })
    const { verifier, challenge } = pkceVerifierAndChallenge()
    const completed = await op.completeConsent({
      client_id: 'spa',
      identity,
      redirect_uri: 'http://localhost/cb',
      scope: ['openid'],
      code_challenge: challenge,
      code_challenge_method: 'S256',
      sid: 'sess-6',
      tenant_id: null,
    })
    if (completed.kind !== 'redirect') throw new Error('expected redirect')
    const code = new URL(completed.url).searchParams.get('code')
    if (code === null) throw new Error('missing code')
    const tok = await op.token(
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://localhost/cb',
        client_id: 'spa',
        code_verifier: verifier,
      },
      new Headers(),
    )
    if ('error' in tok) throw new Error(tok.error)
    const bearer = new Headers({ authorization: `Bearer ${tok.access_token}` })
    // Another client cannot revoke it (RFC 7009 section 2.1), credentials or not.
    const basic = Buffer.from(`resource:${client_secret}`).toString('base64')
    expect(
      await op.revoke(
        { token: tok.access_token, token_type_hint: 'access_token' },
        new Headers({ authorization: `Basic ${basic}` }),
      ),
    ).toBeUndefined()
    expect('error' in (await op.userinfo(bearer))).toBe(false)
    // Its own public client can, naming itself in the body.
    expect(
      await op.revoke({ token: tok.access_token, token_type_hint: 'access_token', client_id: 'spa' }, new Headers()),
    ).toBeUndefined()
    expect('error' in (await op.userinfo(bearer))).toBe(true)
  })
})

describe('AuthOidcOpRoot - who may revoke, introspect and refresh, and for which subject', () => {
  let auth: ReturnType<typeof buildAuth>
  let op: OidcOpRoot<ProfileShape>
  let identity: Identities.Me<ProfileShape>
  const { verifier, challenge } = pkceVerifierAndChallenge()
  const SCOPE = ['openid', 'offline_access']

  beforeEach(async () => {
    auth = buildAuth()
    op = buildOp(auth)
    identity = await auth.identities.create({ profile: { email: 'u@x.com', username: 'u' } })
    for (const client_id of ['spa', 'other-spa']) {
      await op.registerClient({
        client_id,
        redirect_uris: ['http://localhost/cb'],
        scope: SCOPE,
        token_endpoint_auth_method: 'none',
      })
    }
  })

  async function tokensFor(client_id: string, extra: { client_secret?: string; pkce?: boolean } = {}) {
    const pkce = extra.pkce ?? true
    const completed = await op.completeConsent({
      client_id,
      identity,
      redirect_uri: 'http://localhost/cb',
      scope: SCOPE,
      ...(pkce && { code_challenge: challenge, code_challenge_method: 'S256' }),
      sid: 'sess',
      tenant_id: null,
    })
    if (completed.kind !== 'redirect') throw new Error(`expected redirect, got ${completed.kind}`)
    const code = new URL(completed.url).searchParams.get('code') ?? ''
    const tok = await op.token(
      {
        client_id,
        code,
        grant_type: 'authorization_code',
        redirect_uri: 'http://localhost/cb',
        ...(pkce && { code_verifier: verifier }),
        ...(extra.client_secret !== undefined && { client_secret: extra.client_secret }),
      },
      new Headers(),
    )
    if ('error' in tok) throw new Error(tok.error)
    return { access: tok.access_token, refresh: tok.refresh_token ?? '' }
  }

  const refresh = (client_id: string, refresh_token: string, client_secret?: string) =>
    op.token(
      { client_id, grant_type: 'refresh_token', refresh_token, ...(client_secret !== undefined && { client_secret }) },
      new Headers(),
    )

  it('lets a public client revoke its own refresh token by client_id in the body, where it was a no-op', async () => {
    const { refresh: rt } = await tokensFor('spa')
    expect(await op.revoke({ client_id: 'spa', token: rt }, new Headers())).toBeUndefined()
    expect(await refresh('spa', rt)).toMatchObject({ error: 'invalid_grant' })
  })

  it('answers invalid_client to a revoke that names no client, and leaves the token live', async () => {
    const { refresh: rt } = await tokensFor('spa')
    expect(await op.revoke({ token: rt }, new Headers())).toMatchObject({ error: 'invalid_client' })
    expect(await refresh('spa', rt)).not.toHaveProperty('error')
  })

  it('takes client_secret_post credentials from the body for revoke and introspect', async () => {
    const { client_secret } = await op.registerClient({
      client_id: 'post',
      redirect_uris: ['http://localhost/cb'],
      scope: SCOPE,
      token_endpoint_auth_method: 'client_secret_post',
    })
    if (!client_secret) throw new Error('expected a secret')
    const { access, refresh: rt } = await tokensFor('post', { client_secret, pkce: false })
    const creds = { client_id: 'post', client_secret }
    expect(await op.introspect({ ...creds, token: access }, new Headers())).toMatchObject({ active: true })
    expect(await op.introspect({ client_id: 'post', client_secret: 'wrong', token: access }, new Headers())).toEqual({
      active: false,
    })
    expect(await op.revoke({ ...creds, token: rt }, new Headers())).toBeUndefined()
    expect(await refresh('post', rt, client_secret)).toMatchObject({ error: 'invalid_grant' })
  })

  it("does not let one client revoke another's refresh token", async () => {
    const { refresh: rt } = await tokensFor('spa')
    expect(await op.revoke({ client_id: 'other-spa', token: rt }, new Headers())).toBeUndefined()
    expect(await refresh('spa', rt)).not.toHaveProperty('error')
  })

  it("checks the binding before spending a refresh token, so another client's attempt does not burn the owner's", async () => {
    const { refresh: rt } = await tokensFor('spa')
    expect(await refresh('other-spa', rt)).toMatchObject({ error: 'invalid_grant' })
    expect(await refresh('spa', rt)).not.toHaveProperty('error')
  })

  it('ends the grant of a subject since erased: no refresh, and its tokens introspect inactive', async () => {
    const { client_secret } = await op.registerClient({
      client_id: 'rs',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'client_secret_basic',
    })
    const basic = new Headers({ authorization: `Basic ${Buffer.from(`rs:${client_secret}`).toString('base64')}` })
    const { access, refresh: rt } = await tokensFor('spa')
    expect(await op.introspect({ token: access }, basic)).toMatchObject({ active: true, sub: identity.id })
    expect(await op.introspect({ token: rt, token_type_hint: 'refresh_token' }, basic)).toMatchObject({ active: true })
    await auth.identities.erase(identity.id, { reason: 'test' }).orNull()
    expect(await op.introspect({ token: access }, basic)).toEqual({ active: false })
    expect(await op.introspect({ token: rt, token_type_hint: 'refresh_token' }, basic)).toEqual({ active: false })
    expect(await refresh('spa', rt)).toMatchObject({ error: 'invalid_grant' })
  })

  it('refuses a code minted for a subject erased before it was exchanged', async () => {
    const completed = await op.completeConsent({
      client_id: 'spa',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      identity,
      redirect_uri: 'http://localhost/cb',
      scope: SCOPE,
      sid: 'sess',
      tenant_id: null,
    })
    if (completed.kind !== 'redirect') throw new Error('expected redirect')
    const code = new URL(completed.url).searchParams.get('code') ?? ''
    await auth.identities.erase(identity.id, { reason: 'test' }).orNull()
    const tok = await op.token(
      {
        client_id: 'spa',
        code,
        code_verifier: verifier,
        grant_type: 'authorization_code',
        redirect_uri: 'http://localhost/cb',
      },
      new Headers(),
    )
    expect(tok).toMatchObject({ error: 'invalid_grant' })
  })

  it('re-checks scope and PKCE at completeConsent, whose input came back through the host form', async () => {
    const base = {
      client_id: 'spa',
      identity,
      redirect_uri: 'http://localhost/cb',
      sid: 'sess',
      tenant_id: null,
    }
    const pkce = { code_challenge: challenge, code_challenge_method: 'S256' }
    const refused = [
      { ...base, scope: SCOPE },
      { ...base, ...pkce, scope: ['openid', 'email'] },
      { ...base, ...pkce, scope: ['offline_access'] },
      { ...base, code_challenge: challenge, code_challenge_method: 'plain', scope: SCOPE },
    ]
    for (const input of refused) {
      expect(await op.completeConsent(input)).toMatchObject({ kind: 'error', status: 400 })
    }
    expect(await op.completeConsent({ ...base, ...pkce, scope: SCOPE })).toMatchObject({ kind: 'redirect' })
  })

  // Ported from better-auth's GHSA-pw9m-5jxm-xr6h, where the refresh grant checked the token and the
  // client_id, which is public, and never the secret.
  it('will not refresh a confidential client without its secret, and a refused attempt does not burn it', async () => {
    const { client_secret } = await op.registerClient({
      client_id: 'conf',
      redirect_uris: ['http://localhost/cb'],
      scope: SCOPE,
      token_endpoint_auth_method: 'client_secret_post',
    })
    if (!client_secret) throw new Error('expected a secret')
    const { refresh: rt } = await tokensFor('conf', { client_secret, pkce: false })
    expect(await refresh('conf', rt)).toMatchObject({ error: 'invalid_client' })
    expect(await refresh('conf', rt, 'wrong')).toMatchObject({ error: 'invalid_client' })
    expect(await refresh('conf', rt, client_secret)).not.toHaveProperty('error')
  })
})

describe('AuthOidcOpRoot.authorize - a demand for a fresh sign-in, by prompt=login or max_age', () => {
  let ask: (extra?: { prompt?: string; max_age?: string }) => Promise<OidcOP.AuthorizeResult<ProfileShape>>

  // A session whose only factor was presented an hour ago.
  beforeEach(async () => {
    const auth = buildAuth()
    const op = buildOp(auth)
    await op.registerClient({
      client_id: 'spa',
      redirect_uris: ['http://localhost/cb'],
      scope: ['openid'],
      token_endpoint_auth_method: 'none',
    })
    const identity = await auth.identities.create({ profile: { email: 'u@x.com', username: 'u' } })
    const { sid } = await auth.sessions.create({
      aal: 1,
      factors: [{ completedAt: new Date(Date.now() - 3_600_000), method: 'password' }],
      identityId: identity.id,
      kind: 'user',
    })
    const { challenge } = pkceVerifierAndChallenge()
    const pkce = { code_challenge: challenge, code_challenge_method: 'S256' }
    await op.completeConsent({
      ...pkce,
      client_id: 'spa',
      identity,
      redirect_uri: 'http://localhost/cb',
      scope: ['openid'],
      sid: 'sess',
      tenant_id: null,
    })
    ask = (extra = {}) =>
      op.authorize(
        {
          ...pkce,
          ...extra,
          client_id: 'spa',
          redirect_uri: 'http://localhost/cb',
          response_type: 'code',
          scope: 'openid',
        },
        { headers: new Headers({ cookie: `duck-sid=${sid}` }) },
      )
  })

  it('sends a signed-in person back to sign in for prompt=login, alone or with consent', async () => {
    for (const prompt of ['login', 'login consent', 'consent  login']) {
      expect(await ask({ prompt })).toEqual({ kind: 'login_required', reason: 'prompt_login' })
    }
    // `none` with anything else is a contradiction (OIDC Core 3.1.2.1).
    expect(await ask({ prompt: 'none login' })).toMatchObject({ kind: 'error', body: { error: 'invalid_request' } })
    // Resumed without `login`, as the host does once the person has signed in again.
    expect(await ask()).toMatchObject({ kind: 'redirect' })
    expect(await ask({ prompt: 'none' })).toMatchObject({ kind: 'redirect' })
    expect(await ask({ prompt: 'consent' })).toMatchObject({ kind: 'consent_required' })
  })

  it('sends them back to sign in once max_age has passed since their last factor, where max_age was dropped', async () => {
    expect(await ask({ max_age: '60' })).toEqual({ kind: 'login_required', reason: 'max_age_exceeded' })
    expect(await ask({ max_age: '0' })).toEqual({ kind: 'login_required', reason: 'max_age_exceeded' })
    expect(await ask({ max_age: '60', prompt: 'none' })).toMatchObject({
      kind: 'error',
      body: { error: 'login_required' },
    })
    expect(await ask({ max_age: '7200' })).toMatchObject({ kind: 'redirect' })
    for (const max_age of ['', '-1', '1.5', '1e3', 'abc', '99999999999']) {
      expect(await ask({ max_age })).toMatchObject({ kind: 'error', body: { error: 'invalid_request' } })
    }
  })

  it('treats max_age=0 as prompt=login, even straight after a sign-in', async () => {
    const auth = buildAuth()
    const op = buildOp(auth)
    await op.registerClient({
      client_id: 'spa',
      redirect_uris: ['http://localhost/cb'],
      scope: ['openid'],
      token_endpoint_auth_method: 'none',
    })
    const identity = await auth.identities.create({ profile: { email: 'u@x.com', username: 'u' } })
    const now = new Date()
    vi.useFakeTimers({ now, toFake: ['Date'] })
    try {
      const { sid } = await auth.sessions.create({
        aal: 1,
        factors: [{ completedAt: now, method: 'password' }],
        identityId: identity.id,
        kind: 'user',
      })
      const { challenge } = pkceVerifierAndChallenge()
      const result = await op.authorize(
        {
          client_id: 'spa',
          code_challenge: challenge,
          code_challenge_method: 'S256',
          max_age: '0',
          redirect_uri: 'http://localhost/cb',
          response_type: 'code',
          scope: 'openid',
        },
        { headers: new Headers({ cookie: `duck-sid=${sid}` }) },
      )
      expect(result).toEqual({ kind: 'login_required', reason: 'max_age_exceeded' })
    } finally {
      vi.useRealTimers()
    }
  })
})

describe('AuthOidcOpRoot - the tenant', () => {
  async function setup() {
    const auth = buildAuth()
    const op = buildOp(auth)
    await op.registerClient({
      client_id: 'spa',
      redirect_uris: ['http://localhost/cb'],
      scope: ['openid'],
      token_endpoint_auth_method: 'none',
    })
    const identity = await auth.identities.create({ profile: { email: 'u@x.com', username: 'u' } })
    return { auth, identity, op }
  }

  it("authorize reads a tenant's session as signed out to a call naming no tenant, and accepts it named", async () => {
    const { auth, identity, op } = await setup()
    const { sid } = await auth.sessions.create({
      aal: 1,
      factors: [{ completedAt: new Date(), method: 'password' }],
      identityId: identity.id,
      kind: 'user',
      tenantId: 'acme',
    })
    const { challenge } = pkceVerifierAndChallenge()
    const req = {
      client_id: 'spa',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      redirect_uri: 'http://localhost/cb',
      response_type: 'code',
      scope: 'openid',
    }
    const httpReq = { headers: new Headers({ cookie: `duck-sid=${sid}` }) }

    expect(await op.authorize(req, httpReq)).toEqual({ kind: 'login_required', reason: 'no_session' })
    expect(await op.authorize(req, httpReq, { tenantId: 'acme' })).toMatchObject({ kind: 'consent_required' })
  })

  it("userinfo refuses a tenant's token to a call naming no tenant, and answers it named", async () => {
    const { identity, op } = await setup()
    const { verifier, challenge } = pkceVerifierAndChallenge()
    const completed = await op.completeConsent({
      client_id: 'spa',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      identity,
      redirect_uri: 'http://localhost/cb',
      scope: ['openid'],
      sid: 'sess',
      tenant_id: 'acme',
    })
    if (completed.kind !== 'redirect') throw new Error(`expected redirect, got ${completed.kind}`)
    const tok = await op.token(
      {
        client_id: 'spa',
        code: new URL(completed.url).searchParams.get('code') ?? '',
        code_verifier: verifier,
        grant_type: 'authorization_code',
        redirect_uri: 'http://localhost/cb',
      },
      new Headers(),
    )
    if ('error' in tok) throw new Error(tok.error)
    const bearer = new Headers({ authorization: `Bearer ${tok.access_token}` })

    expect(await op.userinfo(bearer)).toMatchObject({ error: 'invalid_token' })
    expect(await op.userinfo(bearer, { tenantId: 'acme' })).toMatchObject({ sub: identity.id })
  })
})
