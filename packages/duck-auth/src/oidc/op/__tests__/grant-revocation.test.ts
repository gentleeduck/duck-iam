/**
 * Ending a grant ends both kinds of token it issued: on refresh-token reuse (RFC 6819 5.2.2.3) and on an
 * RFC 7009 revocation of the refresh token. Ported from better-auth's `oidc.test.ts` token lifecycle cases.
 */
import { createHmac } from 'node:crypto'
import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import type { Identities } from '~/core'
import { sha256 } from '~/core/crypto'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { passwords } from '~/providers/passwords'
import { ScryptHasher } from '~/providers/passwords/hashers/scrypt'
import { createOidcOP, type OidcOpRoot } from '../index'

interface ProfileShape extends Identities.ProfileMetadataBase {}

const SCOPE = ['openid', 'offline_access']
const REDIRECT = 'http://localhost/cb'
const VERIFIER = 'v'.repeat(64)
const CHALLENGE = Buffer.from(sha256(VERIFIER), 'hex').toString('base64url')

function buildAuth() {
  const adapter = new MemoryAdapter<ProfileShape>()
  return new AuthEngine<ProfileShape>({
    baseUrl: 'http://localhost:8787',
    providers: [passwords({ hasher: new ScryptHasher() })],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid' }),
  })
}

function buildOp(auth: ReturnType<typeof buildAuth>): OidcOpRoot<ProfileShape> {
  return createOidcOP<ProfileShape>({
    auth,
    config: { issuer: 'http://localhost:8787/auth', supportedScopes: SCOPE },
    signIdToken: (payload) => {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
      const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
      return `${header}.${body}.${createHmac('sha256', 'dev').update(`${header}.${body}`).digest('base64url')}`
    },
  })
}

describe('a grant that ends', () => {
  let auth: ReturnType<typeof buildAuth>
  let op: OidcOpRoot<ProfileShape>
  let identity: Identities.Me<ProfileShape>
  let secret: string

  /** One grant, taken from consent through to its first pair of tokens. */
  async function grant(): Promise<{ access_token: string; refresh_token: string }> {
    const out = await op.completeConsent({
      client_id: 'app',
      code_challenge: CHALLENGE,
      code_challenge_method: 'S256',
      identity,
      redirect_uri: REDIRECT,
      scope: SCOPE,
      sid: 'sess',
      tenant_id: null,
    })
    if (out.kind !== 'redirect') throw new Error(`expected a redirect, got ${out.kind}`)
    const code = new URL(out.url).searchParams.get('code')
    if (code === null) throw new Error('no code on the redirect')
    const tokens = await op.token(
      {
        client_id: 'app',
        client_secret: secret,
        code,
        code_verifier: VERIFIER,
        grant_type: 'authorization_code',
        redirect_uri: REDIRECT,
      },
      new Headers(),
    )
    if ('error' in tokens) throw new Error(tokens.error)
    if (tokens.refresh_token === undefined) throw new Error('no refresh token')
    return { access_token: tokens.access_token, refresh_token: tokens.refresh_token }
  }

  async function refresh(refresh_token: string) {
    return op.token(
      { client_id: 'app', client_secret: secret, grant_type: 'refresh_token', refresh_token },
      new Headers(),
    )
  }

  /** A refresh that must have succeeded, with the rotated refresh token narrowed. */
  async function rotate(refresh_token: string): Promise<{ access_token: string; refresh_token: string }> {
    const out = await refresh(refresh_token)
    if ('error' in out) throw new Error(out.error)
    if (out.refresh_token === undefined) throw new Error('no rotated refresh token')
    return { access_token: out.access_token, refresh_token: out.refresh_token }
  }

  async function bearer(access_token: string) {
    return op.userinfo(new Headers({ authorization: `Bearer ${access_token}` }))
  }

  beforeEach(async () => {
    auth = buildAuth()
    op = buildOp(auth)
    const registered = await op.registerClient({
      client_id: 'app',
      redirect_uris: [REDIRECT],
      scope: SCOPE,
      token_endpoint_auth_method: 'client_secret_post',
    })
    if (registered.client_secret === null) throw new Error('expected a client secret')
    secret = registered.client_secret
    identity = await auth.identities.create({ profile: { email: 'u@x.com', username: 'u' } })
  })

  it('takes every access token with it when a refresh token is replayed', async () => {
    const first = await grant()
    const second = await rotate(first.refresh_token)
    expect(await bearer(second.access_token)).toMatchObject({ sub: identity.id })

    expect(await refresh(first.refresh_token)).toMatchObject({ error: 'invalid_grant' })
    // Reuse means the family leaked, so the tokens of every rotation go, not just the refresh tokens.
    expect(await bearer(first.access_token)).toMatchObject({ error: 'invalid_token' })
    expect(await bearer(second.access_token)).toMatchObject({ error: 'invalid_token' })
  })

  it('takes every access token with it when the refresh token is revoked (RFC 7009)', async () => {
    const first = await grant()
    const second = await rotate(first.refresh_token)

    expect(
      await op.revoke({ client_id: 'app', client_secret: secret, token: second.refresh_token }, new Headers()),
    ).toBeUndefined()
    expect(await refresh(second.refresh_token)).toMatchObject({ error: 'invalid_grant' })
    // RFC 7009 2.1: the access tokens issued under the grant should go with it.
    expect(await bearer(first.access_token)).toMatchObject({ error: 'invalid_token' })
    expect(await bearer(second.access_token)).toMatchObject({ error: 'invalid_token' })
  })

  it('leaves the other grants of the same subject and client alone', async () => {
    const doomed = await grant()
    const live = await grant()

    expect(await refresh(doomed.refresh_token)).not.toHaveProperty('error')
    expect(await refresh(doomed.refresh_token)).toMatchObject({ error: 'invalid_grant' })
    expect(await bearer(doomed.access_token)).toMatchObject({ error: 'invalid_token' })
    expect(await bearer(live.access_token)).toMatchObject({ sub: identity.id })
    expect(await refresh(live.refresh_token)).not.toHaveProperty('error')
  })

  it('revokes one access token by hash without ending the grant', async () => {
    const first = await grant()
    const second = await rotate(first.refresh_token)

    await op.revoke({ client_id: 'app', client_secret: secret, token: first.access_token }, new Headers())
    // A single stolen access token is not a leaked family: the grant keeps working.
    expect(await bearer(first.access_token)).toMatchObject({ error: 'invalid_token' })
    expect(await bearer(second.access_token)).toMatchObject({ sub: identity.id })
    expect(await refresh(second.refresh_token)).not.toHaveProperty('error')
  })
})
