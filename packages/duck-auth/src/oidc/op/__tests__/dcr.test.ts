import { createHmac } from 'node:crypto'
import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import type { Identities } from '~/core'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { passwords } from '~/providers/passwords'
import { ScryptHasher } from '~/providers/passwords/hashers/scrypt'
import { createOidcOP, type OidcOpRoot } from '../index'
import type { OidcOP } from '../types'

interface ProfileShape extends Identities.ProfileMetadataBase {}

function buildAuth() {
  const adapter = new MemoryAdapter<ProfileShape>()
  return new AuthEngine<ProfileShape>({
    baseUrl: 'http://localhost:8787',
    stores: { identities: adapter.identities, credentials: adapter.credentials, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid' }),
    providers: [passwords({ hasher: new ScryptHasher() })],
  })
}

function buildOp(args: { dcr?: OidcOP.DcrCfg } = {}): OidcOpRoot<ProfileShape> {
  const secret = 'dev-hmac-secret'
  return createOidcOP<ProfileShape>({
    auth: buildAuth(),
    config: {
      issuer: 'http://localhost:8787/auth',
      supportedScopes: ['openid', 'profile', 'email', 'offline_access'],
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
  v: { status: 201; body: OidcOP.DcrResponse } | { status: number; body: OidcOP.DcrError },
): v is { status: 201; body: OidcOP.DcrResponse } {
  return v.status === 201
}

function isDcrError(
  v: { status: 201; body: OidcOP.DcrResponse } | { status: number; body: OidcOP.DcrError },
): v is { status: number; body: OidcOP.DcrError } {
  return v.status !== 201
}

describe('AuthOidcOpRoot.register (RFC 7591 DCR)', () => {
  let op: OidcOpRoot<ProfileShape>

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

describe('AuthOidcOpRoot DCR configuration, refused up front', () => {
  const MISCONFIGURED = expect.objectContaining({ code: 'AUTH_MISCONFIGURED' })

  it('refuses an initialAccessToken key holding undefined, as an unset env var gives, which opened registration', async () => {
    expect(() => buildOp({ dcr: { enabled: true, initialAccessToken: undefined } })).toThrow(MISCONFIGURED)
    // Leaving the key out is still how open registration is asked for.
    const open = buildOp({ dcr: { enabled: true } })
    expect((await open.register({ redirect_uris: ['http://localhost/cb'] }, new Headers())).status).toBe(201)
  })

  it('refuses a blank initialAccessToken, which a trimmed presented token matched', async () => {
    for (const initialAccessToken of ['', '   ']) {
      expect(() => buildOp({ dcr: { enabled: true, initialAccessToken } })).toThrow(MISCONFIGURED)
    }
  })

  it('refuses a maxRedirectUris that is not a whole number, which turned the cap off', async () => {
    for (const maxRedirectUris of [Number(undefined), 0, 1.5]) {
      expect(() => buildOp({ dcr: { enabled: true, maxRedirectUris } })).toThrow(MISCONFIGURED)
    }
    const op = buildOp({ dcr: { enabled: true, maxRedirectUris: 2 } })
    const uris = ['http://localhost/a', 'http://localhost/b', 'http://localhost/c']
    expect((await op.register({ redirect_uris: uris }, new Headers())).status).toBe(400)
    expect((await op.register({ redirect_uris: uris.slice(0, 2) }, new Headers())).status).toBe(201)
  })
})

describe('AuthOidcOpRoot.register - client metadata from an untrusted body', () => {
  let op: OidcOpRoot<ProfileShape>
  beforeEach(() => {
    op = buildOp({ dcr: { enabled: true } })
  })

  const BASE = {
    client_uri: 'https://app.example/about',
    grant_types: ['authorization_code'],
    logo_uri: 'https://cdn.example/logo.png',
    redirect_uris: ['http://localhost/cb'],
    response_types: ['code'],
    scope: 'openid',
  }

  it.each([
    ['client_uri', 'a javascript: URL', 'javascript:alert(document.domain)'],
    ['logo_uri', 'a data: URL', 'data:image/svg+xml,<svg onload=alert(1)>'],
    ['client_uri', 'not a URL', 'not a url'],
    ['logo_uri', 'a URL with userinfo', 'https://user:pw@cdn.example/logo.png'],
    ['client_uri', 'over 2048 characters', `https://app.example/${'a'.repeat(2048)}`],
  ])('refuses a %s that is %s, which a consent screen links on the provider origin', async (key, _label, value) => {
    const r = await op.register({ ...BASE, [key]: value }, new Headers())
    expect(r).toMatchObject({ status: 400, body: { error: 'invalid_client_metadata' } })
  })

  it('keeps http(s) metadata URIs', async () => {
    const r = await op.register(BASE, new Headers())
    if (!isDcrSuccess(r)) throw new Error(`expected 201, got ${r.status}`)
    expect(r.body).toMatchObject({ client_uri: BASE.client_uri, logo_uri: BASE.logo_uri })
  })

  it('answers a field of the wrong type as invalid metadata, where it threw a TypeError', async () => {
    const bodies = [
      Object.assign({ ...BASE }, { scope: 42 }),
      Object.assign({ ...BASE }, { grant_types: 42 }),
      Object.assign({ ...BASE }, { grant_types: 'authorization_code' }),
      Object.assign({ ...BASE }, { response_types: {} }),
      Object.assign({ ...BASE }, { response_types: [1] }),
      Object.assign({ ...BASE }, { client_uri: 42 }),
    ]
    for (const body of bodies) {
      expect(await op.register(body, new Headers())).toMatchObject({
        status: 400,
        body: { error: 'invalid_client_metadata' },
      })
    }
  })

  it('refuses the same URIs on the registerClient path', async () => {
    for (const key of ['client_uri', 'logo_uri']) {
      await expect(
        op.registerClient({
          client_id: 'admin-made',
          redirect_uris: ['http://localhost/cb'],
          [key]: 'javascript:alert(1)',
        }),
      ).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
    }
    await expect(
      op.registerClient({
        client_id: 'admin-made',
        client_uri: BASE.client_uri,
        logo_uri: BASE.logo_uri,
        redirect_uris: ['http://localhost/cb'],
      }),
    ).resolves.toMatchObject({ client_id: 'admin-made' })
  })
})
