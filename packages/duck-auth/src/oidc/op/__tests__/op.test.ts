import { createHmac } from 'node:crypto'
import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { Identity } from '~/core'
import { sha256 } from '~/core/crypto'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie'
import { passwordProvider } from '~/providers/password'
import { ScryptHasher } from '~/providers/password/hashers/scrypt.hasher'
import { createOidcOP, type OidcOpRoot } from '../index'
import type { OidcOP } from '../types'

function isoauthError(v: OidcOP.OauthError | object): v is OidcOP.OauthError {
  return 'error' in v && typeof v.error === 'string' && !('sub' in v)
}

interface ProfileShape extends Identity.ProfileMetadataBase {
  name?: string
  email_verified?: boolean
}

function buildAuth() {
  const adapter = new MemoryAdapter<ProfileShape>()
  return new AuthEngine<ProfileShape>({
    baseUrl: 'http://localhost:8787',
    stores: { identities: adapter.identities, credentials: adapter.credentials, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid' }),
    providers: [passwordProvider({ hasher: new ScryptHasher() })],
  })
}

function buildOp(auth: ReturnType<typeof buildAuth>): OidcOpRoot<ProfileShape> {
  const secret = 'dev-hmac-secret'
  return createOidcOP<ProfileShape>({
    auth,
    config: {
      issuer: 'http://localhost:8787/auth',
      supportedScopes: ['openid', 'profile', 'email', 'offline_access'],
      allowHttp: true,
    },
    signIdToken: (payload) => {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
      const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
      const sig = createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url')
      return `${header}.${body}.${sig}`
    },
  })
}

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
    ).rejects.toThrow(/non-loopback http/)
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
    ).rejects.toThrow(/non-loopback/)
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
      profile: { email: 'u@x.com', name: 'Ursula', email_verified: true, username: 'u' },
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
    const basic = Buffer.from(`resource:${client_secret}`).toString('base64')
    await op.revoke(
      { token: tok.access_token, token_type_hint: 'access_token' },
      new Headers({ authorization: `Basic ${basic}` }),
    )
    const ui = await op.userinfo(new Headers({ authorization: `Bearer ${tok.access_token}` }))
    expect('error' in ui).toBe(true)
  })
})
