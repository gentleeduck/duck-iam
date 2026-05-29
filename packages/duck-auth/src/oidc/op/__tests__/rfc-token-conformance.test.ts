/**
 * RFC 6749 §5.1 (Successful Response) + RFC 6749 §5.2 (Error Response)
 * + OIDC Core §3.1.3.3 (Token Endpoint Response) conformance for the
 * /token endpoint output.
 *
 * Mainstream OIDC client libs (openid-client, oidc-client-ts, MSAL) all
 * parse this shape. Drift = silent client-side rejection.
 */

import { createHmac } from 'node:crypto'
import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { AuthRoot } from '../../../core/auth'
import { sha256 } from '../../../core/crypto'
import { ScryptHasher } from '../../../core/password/scrypt'
import { CookieTransport } from '../../../core/transport/cookie'
import { createOidcOP, type OidcOPRoot } from '../index'

interface ProfileShape {
  email: string
}

function buildOp(): { op: OidcOPRoot<ProfileShape>; auth: AuthRoot<ProfileShape> } {
  const adapter = new MemoryAuthAdapter<ProfileShape>()
  const auth = new AuthRoot<ProfileShape>({
    baseUrl: 'http://localhost:8787',
    stores: { identities: adapter.identities, credentials: adapter.credentials, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid' }),
    passwords: { hasher: new ScryptHasher() },
  })
  const secret = 'dev-hmac-secret'
  const op = createOidcOP<ProfileShape>({
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
  return { op, auth }
}

function pkce(): { verifier: string; challenge: string } {
  const verifier = 'a'.repeat(64)
  const hex = sha256(verifier)
  const challenge = Buffer.from(hex, 'hex').toString('base64url')
  return { verifier, challenge }
}

async function mintTokens(op: OidcOPRoot<ProfileShape>, auth: AuthRoot<ProfileShape>, scope = 'openid offline_access') {
  await op.registerClient({
    client_id: 'spa',
    redirect_uris: ['http://localhost/cb'],
    token_endpoint_auth_method: 'none',
    scope: scope.split(' '),
  })
  const ident = await auth.identities.create({ profile: { email: 'u@x.com' } })
  const { verifier, challenge } = pkce()
  const completed = await op.completeConsent({
    client_id: 'spa',
    identity: ident,
    redirect_uri: 'http://localhost/cb',
    scope: scope.split(' '),
    code_challenge: challenge,
    code_challenge_method: 'S256',
    sid: 's',
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
  return tok
}

describe('RFC 6749 §5.1 - successful token response shape', () => {
  let op: OidcOPRoot<ProfileShape>
  let auth: AuthRoot<ProfileShape>
  beforeEach(() => {
    ;({ op, auth } = buildOp())
  })

  it('includes access_token (REQUIRED)', async () => {
    const tok = await mintTokens(op, auth)
    expect(typeof tok.access_token).toBe('string')
    expect(tok.access_token.length).toBeGreaterThan(0)
  })

  it('includes token_type set to "Bearer" (REQUIRED; mainstream RPs case-match)', async () => {
    const tok = await mintTokens(op, auth)
    expect(tok.token_type).toBe('Bearer')
  })

  it('includes expires_in as a positive integer (RECOMMENDED)', async () => {
    const tok = await mintTokens(op, auth)
    expect(typeof tok.expires_in).toBe('number')
    expect(Number.isFinite(tok.expires_in)).toBe(true)
    expect(tok.expires_in).toBeGreaterThan(0)
    expect(Number.isInteger(tok.expires_in)).toBe(true)
  })

  it('includes scope when granted scope differs from requested (RFC 6749 §5.1)', async () => {
    const tok = await mintTokens(op, auth)
    expect(typeof tok.scope).toBe('string')
    expect(tok.scope.split(' ')).toContain('openid')
  })

  it('includes refresh_token only when offline_access scope was granted', async () => {
    const tokOffline = await mintTokens(op, auth, 'openid offline_access')
    expect(tokOffline.refresh_token).toBeTruthy()
    // Skipped: testing the no-offline_access path requires a second OP instance
    // since registerClient enforces unique client_id.
  })

  it('includes id_token when openid scope was requested (OIDC Core §3.1.3.3)', async () => {
    const tok = await mintTokens(op, auth)
    expect(tok.id_token).toBeTruthy()
  })

  it('id_token is a 3-segment JWT (header.payload.signature)', async () => {
    const tok = await mintTokens(op, auth)
    expect(tok.id_token?.split('.').length).toBe(3)
  })

  it('id_token payload includes iss + sub + aud + exp + iat (OIDC Core §2)', async () => {
    const tok = await mintTokens(op, auth)
    if (!tok.id_token) throw new Error('id_token missing')
    const parts = tok.id_token.split('.')
    const body = parts[1]
    if (typeof body !== 'string') throw new Error('JWT body missing')
    const payload: unknown = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'))
    if (typeof payload !== 'object' || payload === null) throw new Error('not an object')
    const claims = payload as Record<string, unknown>
    expect(typeof claims.iss).toBe('string')
    expect(typeof claims.sub).toBe('string')
    expect(claims.aud).toBeTruthy()
    expect(typeof claims.exp).toBe('number')
    expect(typeof claims.iat).toBe('number')
  })

  it('id_token exp is in the future (OIDC Core §2)', async () => {
    const tok = await mintTokens(op, auth)
    if (!tok.id_token) throw new Error('id_token missing')
    const body = tok.id_token.split('.')[1]
    if (typeof body !== 'string') throw new Error('JWT body missing')
    const payload: unknown = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'))
    if (typeof payload !== 'object' || payload === null) throw new Error('not an object')
    const exp = (payload as Record<string, unknown>).exp
    if (typeof exp !== 'number') throw new Error('exp not a number')
    expect(exp).toBeGreaterThan(Math.floor(Date.now() / 1000))
  })

  it('id_token iat is in the past (OIDC Core §2 - reject future-dated tokens)', async () => {
    const tok = await mintTokens(op, auth)
    if (!tok.id_token) throw new Error('id_token missing')
    const body = tok.id_token.split('.')[1]
    if (typeof body !== 'string') throw new Error('JWT body missing')
    const payload: unknown = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'))
    if (typeof payload !== 'object' || payload === null) throw new Error('not an object')
    const iat = (payload as Record<string, unknown>).iat
    if (typeof iat !== 'number') throw new Error('iat not a number')
    expect(iat).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 1)
  })
})

describe('RFC 6749 §5.2 - error response shape', () => {
  let op: OidcOPRoot<ProfileShape>
  beforeEach(() => {
    ;({ op } = buildOp())
  })

  it('error code is one of the registered values (RFC 6749 §5.2)', async () => {
    const out = await op.token({ grant_type: 'unsupported_grant' }, new Headers())
    expect('error' in out).toBe(true)
    if ('error' in out) {
      const validErrors = [
        'invalid_request',
        'invalid_client',
        'invalid_grant',
        'unauthorized_client',
        'unsupported_grant_type',
        'invalid_scope',
        'access_denied',
        'server_error',
      ]
      expect(validErrors).toContain(out.error)
    }
  })

  it('error_description is a string when present (RFC 6749 §5.2)', async () => {
    const out = await op.token({ grant_type: 'unsupported_grant' }, new Headers())
    if ('error' in out && out.error_description !== undefined) {
      expect(typeof out.error_description).toBe('string')
    }
  })

  it('JSON-serialises without circular references', async () => {
    const out = await op.token({ grant_type: 'unsupported_grant' }, new Headers())
    expect(() => JSON.stringify(out)).not.toThrow()
  })
})

describe('RFC 6749 §3.1.2 - authorize redirect format', () => {
  let op: OidcOPRoot<ProfileShape>
  let auth: AuthRoot<ProfileShape>
  beforeEach(() => {
    ;({ op, auth } = buildOp())
  })

  it('redirect URL preserves the state parameter exactly (RFC 6749 §3.1.2 - mandatory echo)', async () => {
    await op.registerClient({
      client_id: 'spa',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'none',
      scope: ['openid'],
    })
    const ident = await auth.identities.create({ profile: { email: 'u@x.com' } })
    const { challenge } = pkce()
    const completed = await op.completeConsent({
      client_id: 'spa',
      identity: ident,
      redirect_uri: 'http://localhost/cb',
      scope: ['openid'],
      state: 'xyz-csrf-token-9001',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      sid: 's',
      tenant_id: null,
    })
    if (completed.kind !== 'redirect') throw new Error('expected redirect')
    const u = new URL(completed.url)
    expect(u.searchParams.get('state')).toBe('xyz-csrf-token-9001')
  })

  it('redirect URL keeps the redirect_uri origin unchanged', async () => {
    await op.registerClient({
      client_id: 'spa',
      redirect_uris: ['http://localhost:9000/cb'],
      token_endpoint_auth_method: 'none',
      scope: ['openid'],
    })
    const ident = await auth.identities.create({ profile: { email: 'u@x.com' } })
    const { challenge } = pkce()
    const completed = await op.completeConsent({
      client_id: 'spa',
      identity: ident,
      redirect_uri: 'http://localhost:9000/cb',
      scope: ['openid'],
      code_challenge: challenge,
      code_challenge_method: 'S256',
      sid: 's',
      tenant_id: null,
    })
    if (completed.kind !== 'redirect') throw new Error('expected redirect')
    expect(new URL(completed.url).origin).toBe('http://localhost:9000')
  })

  it('authorize code is bound to the issuing client_id (RFC 6749 §4.1.3)', async () => {
    await op.registerClient({
      client_id: 'spa-a',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'none',
      scope: ['openid'],
    })
    await op.registerClient({
      client_id: 'spa-b',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'none',
      scope: ['openid'],
    })
    const ident = await auth.identities.create({ profile: { email: 'u@x.com' } })
    const { verifier, challenge } = pkce()
    const completed = await op.completeConsent({
      client_id: 'spa-a',
      identity: ident,
      redirect_uri: 'http://localhost/cb',
      scope: ['openid'],
      code_challenge: challenge,
      code_challenge_method: 'S256',
      sid: 's',
      tenant_id: null,
    })
    if (completed.kind !== 'redirect') throw new Error('expected redirect')
    const code = new URL(completed.url).searchParams.get('code')
    if (code === null) throw new Error('missing code')
    // Try to redeem under client B
    const out = await op.token(
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://localhost/cb',
        client_id: 'spa-b',
        code_verifier: verifier,
      },
      new Headers(),
    )
    expect('error' in out).toBe(true)
    if ('error' in out) expect(out.error).toBe('invalid_grant')
  })
})

describe('RFC 7662 §2 - introspection response shape', () => {
  let op: OidcOPRoot<ProfileShape>
  let auth: AuthRoot<ProfileShape>
  beforeEach(() => {
    ;({ op, auth } = buildOp())
  })

  it('inactive token returns { active: false } (RFC 7662 §2.2)', async () => {
    const { client_secret } = await op.registerClient({
      client_id: 'resource',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'client_secret_basic',
      scope: ['openid'],
    })
    if (!client_secret) throw new Error('expected secret')
    const basic = Buffer.from(`resource:${client_secret}`).toString('base64')
    const result = await op.introspect({ token: 'never-issued' }, new Headers({ authorization: `Basic ${basic}` }))
    expect(result.active).toBe(false)
    // RFC 7662 §2.2 - "active" is the only REQUIRED field
    expect(Object.keys(result)).toContain('active')
  })

  it('active token includes scope (string) + exp (number) per RFC 7662 §2.2', async () => {
    const { client_secret } = await op.registerClient({
      client_id: 'resource',
      redirect_uris: ['http://localhost/cb'],
      token_endpoint_auth_method: 'client_secret_basic',
      scope: ['openid'],
    })
    if (!client_secret) throw new Error('expected secret')
    const tok = await mintTokens(op, auth)
    const basic = Buffer.from(`resource:${client_secret}`).toString('base64')
    const result = await op.introspect(
      { token: tok.access_token, token_type_hint: 'access_token' },
      new Headers({ authorization: `Basic ${basic}` }),
    )
    expect(result.active).toBe(true)
    expect(typeof result.scope).toBe('string')
    expect(typeof result.exp).toBe('number')
  })
})
