/**
 * `client_secret_basic`, as RFC 6749 section 2.3.1 defines it.
 *
 * The spec does not say `base64(id + ':' + secret)`. It says each half is
 * encoded with the `application/x-www-form-urlencoded` algorithm *first*, and
 * the result of that is what gets base64'd. A conforming client therefore sends
 * a secret of `s3cr3t key` as `s3cr3t+key`, and one containing `+` as `%2B`.
 *
 * `parseBasicAuth` base64-decoded and split on the first colon, so a client that
 * followed the spec authenticated against the wrong string and was refused. It
 * never showed with a secret this library generated: `randomToken` returns
 * base64url, whose alphabet form-encoding leaves untouched. It shows the moment
 * a host registers a client with a secret of its own.
 *
 * The decode is lenient on purpose — a client that skips the encoding still
 * works, because the raw spelling is tried as a second candidate. Both
 * candidates are compared against the stored hash, so neither widens what a
 * caller has to know.
 *
 * Seam is `op.introspect`, which is the shortest public path through
 * `authenticateClient`.
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

function build() {
  const adapter = new MemoryAdapter<Identities.ProfileMetadataBase>()
  const auth = new AuthEngine<Identities.ProfileMetadataBase>({
    baseUrl: 'http://localhost:8787',
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid' }),
    providers: [passwords({ hasher: new ScryptHasher() })],
  })
  const op = createOidcOP<Identities.ProfileMetadataBase>({
    auth,
    config: { allowHttp: true, issuer: 'http://localhost:8787/auth', supportedScopes: ['openid'] },
    signIdToken: (payload) => {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
      const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
      return `${header}.${body}.${createHmac('sha256', 'k').update(`${header}.${body}`).digest('base64url')}`
    },
  })
  return { auth, op }
}

/** A live access token belonging to a public client, for the resource server to introspect. */
async function mintAccessToken(
  auth: ReturnType<typeof build>['auth'],
  op: OidcOpRoot<Identities.ProfileMetadataBase>,
): Promise<string> {
  await op.registerClient({
    client_id: 'spa',
    redirect_uris: ['http://localhost/cb'],
    scope: ['openid'],
    token_endpoint_auth_method: 'none',
  })
  const identity = await auth.identities.create({ profile: { email: 'u@x.com', username: 'u' } })
  const verifier = 'a'.repeat(64)
  const challenge = Buffer.from(sha256(verifier), 'hex').toString('base64url')
  const completed = await op.completeConsent({
    client_id: 'spa',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    identity,
    redirect_uri: 'http://localhost/cb',
    scope: ['openid'],
    sid: 'sess-1',
    tenant_id: null,
  })
  if (completed.kind !== 'redirect') throw new Error('expected redirect')
  const code = new URL(completed.url).searchParams.get('code')
  if (code === null) throw new Error('missing code')
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
  if ('error' in tok) throw new Error(`token: ${tok.error}`)
  return tok.access_token
}

/** The encoding RFC 6749 section 2.3.1 asks a client to apply to each half. */
function formEncode(value: string): string {
  return encodeURIComponent(value).replace(/%20/g, '+')
}

const basicHeader = (id: string, secret: string): Headers =>
  new Headers({ authorization: `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}` })

describe('client_secret_basic form-decodes each half, per RFC 6749 section 2.3.1', () => {
  let op: OidcOpRoot<Identities.ProfileMetadataBase>
  let token: string

  beforeEach(async () => {
    const built = build()
    op = built.op
    token = await mintAccessToken(built.auth, built.op)
  })

  /**
   * `active === true` is the only observable proof the resource server
   * authenticated: `introspect` answers `{ active: false }` for a refused client
   * exactly as it does for an unknown token, so asserting on an absent `error`
   * passes whether the Basic header worked or not.
   */
  async function authenticates(headers: Headers): Promise<boolean> {
    return (await op.introspect({ token, token_type_hint: 'access_token' }, headers)).active === true
  }

  describe.each([
    ['a space', 'a b secret'],
    ['a plus, which form-encoding turns into %2B', 'a+b+secret'],
    ['a percent', 'pct%20secret'],
    ['a colon, the separator itself', 'left:right'],
    ['an ampersand and an equals', 'a&b=c'],
    ['non-ASCII text', 'sëcrét-ünï'],
  ])('a client secret containing %s', (_label, secret) => {
    it('authenticates when the client encodes it as the spec says', async () => {
      await op.registerClient({
        client_id: 'resource',
        client_secret: secret,
        redirect_uris: ['http://localhost/cb'],
        scope: ['openid'],
        token_endpoint_auth_method: 'client_secret_basic',
      })
      expect(await authenticates(basicHeader('resource', formEncode(secret)))).toBe(true)
    })

    it('still authenticates a client that sends it raw, which is what shipped', async () => {
      await op.registerClient({
        client_id: 'resource',
        client_secret: secret,
        redirect_uris: ['http://localhost/cb'],
        scope: ['openid'],
        token_endpoint_auth_method: 'client_secret_basic',
      })
      expect(await authenticates(basicHeader('resource', secret))).toBe(true)
    })

    it('refuses a wrong secret, in either spelling', async () => {
      await op.registerClient({
        client_id: 'resource',
        client_secret: secret,
        redirect_uris: ['http://localhost/cb'],
        scope: ['openid'],
        token_endpoint_auth_method: 'client_secret_basic',
      })
      expect(await authenticates(basicHeader('resource', `${secret}x`))).toBe(false)
      expect(await authenticates(basicHeader('resource', formEncode(`${secret}x`)))).toBe(false)
    })
  })

  it('finds a client whose id itself needs encoding', async () => {
    await op.registerClient({
      client_id: 'tenant one/app',
      client_secret: 'plain-secret',
      redirect_uris: ['http://localhost/cb'],
      scope: ['openid'],
      token_endpoint_auth_method: 'client_secret_basic',
    })
    expect(await authenticates(basicHeader(formEncode('tenant one/app'), 'plain-secret'))).toBe(true)
  })

  it('leaves invalid percent-encoding alone rather than throwing', async () => {
    // `decodeURIComponent('%zz')` throws. The raw spelling has to survive that.
    await op.registerClient({
      client_id: 'resource',
      client_secret: '100%zz',
      redirect_uris: ['http://localhost/cb'],
      scope: ['openid'],
      token_endpoint_auth_method: 'client_secret_basic',
    })
    expect(await authenticates(basicHeader('resource', '100%zz'))).toBe(true)
  })

  describe('the header rules around the payload', () => {
    beforeEach(async () => {
      await op.registerClient({
        client_id: 'resource',
        client_secret: 'plain-secret',
        redirect_uris: ['http://localhost/cb'],
        scope: ['openid'],
        token_endpoint_auth_method: 'client_secret_basic',
      })
    })

    it('accepts the scheme case-insensitively, per RFC 7235 section 2.1', async () => {
      for (const scheme of ['Basic', 'basic', 'BASIC', 'BaSiC']) {
        const payload = Buffer.from('resource:plain-secret').toString('base64')
        expect(await authenticates(new Headers({ authorization: `${scheme} ${payload}` })), scheme).toBe(true)
      }
    })

    it('accepts more than one space between the scheme and the payload', async () => {
      const payload = Buffer.from('resource:plain-secret').toString('base64')
      expect(await authenticates(new Headers({ authorization: `Basic   ${payload}` }))).toBe(true)
    })

    it('refuses a payload with no separator', async () => {
      const payload = Buffer.from('resourceplain-secret').toString('base64')
      expect(await authenticates(new Headers({ authorization: `Basic ${payload}` }))).toBe(false)
    })

    it('refuses an empty client id, rather than reading one from the body', async () => {
      expect(await authenticates(basicHeader('', 'plain-secret'))).toBe(false)
    })

    it('does not let the body name a different client than the header', async () => {
      // A Basic header owns the client_id. Falling back to `req.client_id` when
      // the header's half is empty would let a caller authenticate as whichever
      // client the body names, using a secret the header carries.
      const res = await op.introspect(
        { client_id: 'resource', token, token_type_hint: 'access_token' },
        basicHeader('', 'plain-secret'),
      )
      expect(res.active).toBe(false)
    })

    it('refuses an empty client secret', async () => {
      expect(await authenticates(basicHeader('resource', ''))).toBe(false)
    })
  })
})
