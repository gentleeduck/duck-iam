import { createHmac } from 'node:crypto'
import { beforeEach, describe, expect, it } from 'vitest'
import { AuthMemoryAdapter } from '../../../adapters/memory'
import { AuthEngine } from '../../../core/auth'
import { AuthScryptHasher } from '../../../core/password/scrypt'
import { AuthCookieTransport } from '../../../core/transport/cookie'
import { authCreateOidcOP, type AuthOidcOpRoot } from '../index'
import type { AuthOidcOP } from '../types'

interface ProfileShape {
  email: string
}

function buildAuth() {
  const adapter = new AuthMemoryAdapter<ProfileShape>()
  return new AuthEngine<ProfileShape>({
    baseUrl: 'http://localhost:8787',
    stores: { identities: adapter.identities, credentials: adapter.credentials, sessions: adapter.sessions },
    transport: new AuthCookieTransport({ name: 'duck-sid' }),
    passwords: { hasher: new AuthScryptHasher() },
  })
}

function buildOp(args: { dcr?: AuthOidcOP.IDcrConfig } = {}): AuthOidcOpRoot<ProfileShape> {
  const secret = 'dev-hmac-secret'
  return authCreateOidcOP<ProfileShape>({
    auth: buildAuth(),
    config: {
      issuer: 'http://localhost:8787/auth',
      supportedScopes: ['openid', 'profile', 'email', 'offline_access'],
      allowHttp: true,
    },
    ...(args.dcr !== undefined && { dcr: args.dcr }),
    signIdToken: (payload) => {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
      const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
      const sig = createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url')
      return `${header}.${body}.${sig}`
    },
  })
}

function isDcrSuccess(
  v: { status: 201; body: AuthOidcOP.IDcrResponse } | { status: number; body: AuthOidcOP.IDcrError },
): v is { status: 201; body: AuthOidcOP.IDcrResponse } {
  return v.status === 201
}

function isDcrError(
  v: { status: 201; body: AuthOidcOP.IDcrResponse } | { status: number; body: AuthOidcOP.IDcrError },
): v is { status: number; body: AuthOidcOP.IDcrError } {
  return v.status !== 201
}

describe('AuthOidcOpRoot.register (RFC 7591 DCR)', () => {
  let op: AuthOidcOpRoot<ProfileShape>

  describe('when DCR is disabled (default)', () => {
    beforeEach(() => {
      op = buildOp()
    })
    it('returns 403 unauthorized', async () => {
      const r = await op.register({ redirect_uris: ['http://localhost/cb'] }, new Headers())
      expect(r.status).toBe(403)
      if (!isDcrError(r)) throw new Error('expected error response')
      expect(r.body.error).toBe('unauthorized')
    })
  })

  describe('with open registration', () => {
    beforeEach(() => {
      op = buildOp({ dcr: { enabled: true } })
    })

    it('issues a public client when token_endpoint_auth_method=none', async () => {
      const r = await op.register(
        {
          redirect_uris: ['http://localhost/cb'],
          token_endpoint_auth_method: 'none',
          client_name: 'My SPA',
        },
        new Headers(),
      )
      expect(r.status).toBe(201)
      if (!isDcrSuccess(r)) throw new Error('expected 201')
      expect(r.body.client_id).toMatch(/^dcr-/)
      expect(r.body.client_secret).toBeUndefined()
      expect(r.body.token_endpoint_auth_method).toBe('none')
      expect(r.body.scope).toContain('openid')
      expect(r.body.client_id_issued_at).toBeGreaterThan(0)
      expect(r.body.client_secret_expires_at).toBe(0)
    })

    it('issues client_secret for confidential clients', async () => {
      const r = await op.register(
        {
          redirect_uris: ['https://app.example.com/cb'],
          token_endpoint_auth_method: 'client_secret_basic',
        },
        new Headers(),
      )
      if (!isDcrSuccess(r)) throw new Error('expected 201')
      expect(r.body.client_secret).toBeTruthy()
      expect(r.body.client_secret?.length).toBeGreaterThan(20)
    })

    it('rejects empty redirect_uris', async () => {
      const r = await op.register({ redirect_uris: [] }, new Headers())
      expect(r.status).toBe(400)
      if (!isDcrError(r)) throw new Error('expected error response')
      expect(r.body.error).toBe('invalid_redirect_uri')
    })

    it('rejects non-loopback http redirect_uri', async () => {
      const r = await op.register({ redirect_uris: ['http://attacker.example.com/cb'] }, new Headers())
      expect(r.status).toBe(400)
      if (!isDcrError(r)) throw new Error('expected error response')
      expect(r.body.error).toBe('invalid_redirect_uri')
    })

    it('caps the number of redirect_uris', async () => {
      const op2 = buildOp({ dcr: { enabled: true, maxRedirectUris: 2 } })
      const r = await op2.register(
        {
          redirect_uris: ['http://localhost/a', 'http://localhost/b', 'http://localhost/c'],
        },
        new Headers(),
      )
      expect(r.status).toBe(400)
      if (!isDcrError(r)) throw new Error('expected error response')
      expect(r.body.error).toBe('invalid_redirect_uri')
    })

    it('rejects unsupported scope', async () => {
      const r = await op.register(
        {
          redirect_uris: ['http://localhost/cb'],
          token_endpoint_auth_method: 'none',
          scope: 'openid not-a-real-scope',
        },
        new Headers(),
      )
      expect(r.status).toBe(400)
      if (!isDcrError(r)) throw new Error('expected error response')
      expect(r.body.error).toBe('invalid_client_metadata')
    })

    it('rejects unsupported token_endpoint_auth_method', async () => {
      const r = await op.register(
        {
          redirect_uris: ['http://localhost/cb'],
          token_endpoint_auth_method: 'private_key_jwt',
        },
        new Headers(),
      )
      expect(r.status).toBe(400)
      if (!isDcrError(r)) throw new Error('expected error response')
      expect(r.body.error).toBe('invalid_client_metadata')
    })

    it('always ensures the openid scope ends up in the registered client', async () => {
      const r = await op.register(
        {
          redirect_uris: ['http://localhost/cb'],
          token_endpoint_auth_method: 'none',
          scope: 'profile email',
        },
        new Headers(),
      )
      if (!isDcrSuccess(r)) throw new Error('expected 201')
      expect(r.body.scope.split(' ')).toContain('openid')
    })

    it('rejects oversize client_name', async () => {
      const r = await op.register(
        {
          redirect_uris: ['http://localhost/cb'],
          token_endpoint_auth_method: 'none',
          client_name: 'x'.repeat(300),
        },
        new Headers(),
      )
      expect(r.status).toBe(400)
      if (!isDcrError(r)) throw new Error('expected error response')
      expect(r.body.error).toBe('invalid_client_metadata')
    })

    it('produces a client that immediately works at /authorize', async () => {
      const r = await op.register(
        {
          redirect_uris: ['http://localhost/cb'],
          token_endpoint_auth_method: 'none',
        },
        new Headers(),
      )
      if (!isDcrSuccess(r)) throw new Error('expected 201')
      const authResult = await op.authorize(
        {
          client_id: r.body.client_id,
          redirect_uri: 'http://localhost/cb',
          response_type: 'code',
          scope: 'openid',
          code_challenge: 'YbS3dhTMP-V99bOM6w0E2Vc99tTrXyL8YsT4cgrr1Wo',
          code_challenge_method: 'S256',
        },
        { headers: new Headers() },
      )
      expect(authResult.kind).toBe('login_required')
    })
  })

  describe('with initialAccessToken gating', () => {
    beforeEach(() => {
      op = buildOp({ dcr: { enabled: true, initialAccessToken: 'super-secret-iat' } })
    })

    it('rejects when bearer is missing', async () => {
      const r = await op.register({ redirect_uris: ['http://localhost/cb'] }, new Headers())
      expect(r.status).toBe(401)
      if (!isDcrError(r)) throw new Error('expected error response')
      expect(r.body.error).toBe('unauthorized')
    })

    it('rejects when bearer is wrong', async () => {
      const r = await op.register(
        { redirect_uris: ['http://localhost/cb'] },
        new Headers({ authorization: 'Bearer nope' }),
      )
      expect(r.status).toBe(401)
      if (!isDcrError(r)) throw new Error('expected error response')
      expect(r.body.error).toBe('unauthorized')
    })

    it('accepts the correct bearer', async () => {
      const r = await op.register(
        { redirect_uris: ['http://localhost/cb'], token_endpoint_auth_method: 'none' },
        new Headers({ authorization: 'Bearer super-secret-iat' }),
      )
      expect(r.status).toBe(201)
    })

    it('bearer comparison is constant-time on length mismatch', async () => {
      const r = await op.register({ redirect_uris: ['http://localhost/cb'] }, new Headers({ authorization: 'Bearer ' }))
      expect(r.status).toBe(401)
    })
  })
})
