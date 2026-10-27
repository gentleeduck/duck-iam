/**
 * A replayed authorization code revokes what the first redemption issued (RFC 6749 4.1.2), reaching every
 * token descended from it, of either kind. Ported from better-auth's `token.test.ts`.
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

/** A verifier per grant, so two grants in one test cannot pass each other's PKCE. */
function pkce(seed: string): { verifier: string; challenge: string } {
  const verifier = seed.repeat(64).slice(0, 64)
  return { challenge: Buffer.from(sha256(verifier), 'hex').toString('base64url'), verifier }
}

describe('an authorization code redeemed twice', () => {
  let auth: ReturnType<typeof buildAuth>
  let op: OidcOpRoot<ProfileShape>
  let identity: Identities.Me<ProfileShape>

  /** One grant taken as far as a code. */
  async function codeFor(clientId: string, seed: string): Promise<{ code: string; verifier: string }> {
    const { verifier, challenge } = pkce(seed)
    const out = await op.completeConsent({
      client_id: clientId,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      identity,
      redirect_uri: REDIRECT,
      scope: SCOPE,
      sid: `sess-${clientId}`,
      tenant_id: null,
    })
    if (out.kind !== 'redirect') throw new Error(`expected a redirect, got ${out.kind}`)
    const code = new URL(out.url).searchParams.get('code')
    if (code === null) throw new Error('no code on the redirect')
    return { code, verifier }
  }

  async function redeem(clientId: string, code: string, verifier: string) {
    return op.token(
      { client_id: clientId, code, code_verifier: verifier, grant_type: 'authorization_code', redirect_uri: REDIRECT },
      new Headers(),
    )
  }

  async function refresh(clientId: string, refresh_token: string) {
    return op.token({ client_id: clientId, grant_type: 'refresh_token', refresh_token }, new Headers())
  }

  async function bearer(access_token: string) {
    return op.userinfo(new Headers({ authorization: `Bearer ${access_token}` }))
  }

  beforeEach(async () => {
    auth = buildAuth()
    op = buildOp(auth)
    await op.registerClient({
      client_id: 'spa',
      redirect_uris: [REDIRECT],
      scope: SCOPE,
      token_endpoint_auth_method: 'none',
    })
    identity = await auth.identities.create({ profile: { email: 'u@x.com', username: 'u' } })
  })

  it('is denied, and the refresh token the first redemption issued dies with it', async () => {
    const { code, verifier } = await codeFor('spa', 'a')
    const first = await redeem('spa', code, verifier)
    if ('error' in first) throw new Error(first.error)
    expect(first.refresh_token).toBeTruthy()

    const replay = await redeem('spa', code, verifier)
    expect(replay).toMatchObject({ error: 'invalid_grant' })
    // The half we were missing: a denial alone leaves a 30-day grant off a 10-minute code.
    expect(await refresh('spa', first.refresh_token ?? '')).toMatchObject({ error: 'invalid_grant' })
  })

  it('reaches a refresh token two rotations away from the code', async () => {
    const { code, verifier } = await codeFor('spa', 'a')
    const first = await redeem('spa', code, verifier)
    if ('error' in first) throw new Error(first.error)
    const second = await refresh('spa', first.refresh_token ?? '')
    if ('error' in second) throw new Error(second.error)
    const third = await refresh('spa', second.refresh_token ?? '')
    if ('error' in third) throw new Error(third.error)

    await redeem('spa', code, verifier)
    // Rotation must not walk the grant out of reach of its own revocation.
    expect(await refresh('spa', third.refresh_token ?? '')).toMatchObject({ error: 'invalid_grant' })
  })

  it('leaves another grant for the same subject and client alone', async () => {
    const live = await codeFor('spa', 'a')
    const doomed = await codeFor('spa', 'b')
    const liveTokens = await redeem('spa', live.code, live.verifier)
    const doomedTokens = await redeem('spa', doomed.code, doomed.verifier)
    if ('error' in liveTokens || 'error' in doomedTokens) throw new Error('setup failed to issue')

    await redeem('spa', doomed.code, doomed.verifier)
    expect(await refresh('spa', doomedTokens.refresh_token ?? '')).toMatchObject({ error: 'invalid_grant' })
    // Per code, not per subject: one replay must not log out the other session.
    const stillGood = await refresh('spa', liveTokens.refresh_token ?? '')
    expect('error' in stillGood).toBe(false)
  })

  it('tolerates a code that was never issued, which is most of what reaches this path', async () => {
    const { code, verifier } = await codeFor('spa', 'a')
    const issued = await redeem('spa', code, verifier)
    if ('error' in issued) throw new Error(issued.error)
    // The ordinary case is a tab left open, so revoking a family that does not exist must be a no-op.
    expect(await redeem('spa', 'never-minted-code', verifier)).toMatchObject({ error: 'invalid_grant' })
    expect('error' in (await refresh('spa', issued.refresh_token ?? ''))).toBe(false)
  })

  it('takes the access token with it, not just the refresh token', async () => {
    const { code, verifier } = await codeFor('spa', 'a')
    const first = await redeem('spa', code, verifier)
    if ('error' in first) throw new Error(first.error)
    expect(await bearer(first.access_token)).toMatchObject({ sub: identity.id })

    await redeem('spa', code, verifier)
    // The access token is the one the thief would actually spend, and it outlives the code it came from.
    expect(await bearer(first.access_token)).toMatchObject({ error: 'invalid_token' })
  })

  it('takes the access token of a later rotation too', async () => {
    const { code, verifier } = await codeFor('spa', 'a')
    const first = await redeem('spa', code, verifier)
    if ('error' in first) throw new Error(first.error)
    const second = await refresh('spa', first.refresh_token ?? '')
    if ('error' in second) throw new Error(second.error)
    expect(await bearer(second.access_token)).toMatchObject({ sub: identity.id })

    await redeem('spa', code, verifier)
    expect(await bearer(second.access_token)).toMatchObject({ error: 'invalid_token' })
  })

  it('leaves the access tokens of another grant alone', async () => {
    const live = await codeFor('spa', 'a')
    const doomed = await codeFor('spa', 'b')
    const liveTokens = await redeem('spa', live.code, live.verifier)
    const doomedTokens = await redeem('spa', doomed.code, doomed.verifier)
    if ('error' in liveTokens || 'error' in doomedTokens) throw new Error('setup failed to issue')

    await redeem('spa', doomed.code, doomed.verifier)
    expect(await bearer(doomedTokens.access_token)).toMatchObject({ error: 'invalid_token' })
    expect(await bearer(liveTokens.access_token)).toMatchObject({ sub: identity.id })
  })
})
