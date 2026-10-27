/**
 * `auth_time` and `sid` reach the id_token and survive a refresh (OIDC Core 3.1.3.6 and 12.2), and `auth_time`
 * is omitted rather than invented when nobody measured it. Ported from better-auth's `oidc.test.ts`.
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
/** Two minutes ago, on a whole second, so the expected claim is an exact division rather than a rounding. */
const AUTH_AT_MS = Math.floor(Date.now() / 1000) * 1000 - 120_000
const AUTH_AT_SECONDS = AUTH_AT_MS / 1000

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

/** The id_token's claims, read without trusting the shape of what came back. */
function claims(token: string | undefined): Map<string, unknown> {
  const body = token?.split('.')[1]
  if (body === undefined) throw new Error('not a JWT')
  const parsed: unknown = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'))
  if (parsed === null || typeof parsed !== 'object') throw new Error('JWT body is not an object')
  return new Map(Object.entries(parsed))
}

describe('the id_token claims that describe the sign-in behind the grant', () => {
  let auth: ReturnType<typeof buildAuth>
  let op: OidcOpRoot<ProfileShape>
  let identity: Identities.Me<ProfileShape>
  let sessionId: string
  let cookie: Headers

  async function authorize() {
    return op.authorize(
      {
        client_id: 'app',
        code_challenge: CHALLENGE,
        code_challenge_method: 'S256',
        redirect_uri: REDIRECT,
        response_type: 'code',
        scope: SCOPE.join(' '),
      },
      { headers: cookie },
    )
  }

  async function redeem(url: string) {
    const code = new URL(url).searchParams.get('code')
    if (code === null) throw new Error('no code on the redirect')
    return op.token(
      { client_id: 'app', code, code_verifier: VERIFIER, grant_type: 'authorization_code', redirect_uri: REDIRECT },
      new Headers(),
    )
  }

  async function refresh(refresh_token: string | undefined) {
    return op.token({ client_id: 'app', grant_type: 'refresh_token', refresh_token }, new Headers())
  }

  beforeEach(async () => {
    auth = buildAuth()
    op = buildOp(auth)
    await op.registerClient({
      client_id: 'app',
      redirect_uris: [REDIRECT],
      scope: SCOPE,
      token_endpoint_auth_method: 'none',
    })
    identity = await auth.identities.create({ profile: { email: 'u@x.com', username: 'u' } })
    const created = await auth.sessions.create({
      aal: 1,
      factors: [{ completedAt: new Date(AUTH_AT_MS), method: 'password' }],
      identityId: identity.id,
      kind: 'user',
    })
    sessionId = created.session.id
    cookie = new Headers({ cookie: `duck-sid=${created.sid}` })
  })

  it('hands `auth_time` back with the consent prompt, and carries it into the id_token', async () => {
    const asked = await authorize()
    expect(asked).toMatchObject({ auth_time: AUTH_AT_MS, kind: 'consent_required' })
    if (asked.kind !== 'consent_required') throw new Error(`expected consent_required, got ${asked.kind}`)

    const completed = await op.completeConsent({
      auth_time: asked.auth_time,
      client_id: 'app',
      code_challenge: CHALLENGE,
      code_challenge_method: 'S256',
      identity,
      redirect_uri: REDIRECT,
      scope: SCOPE,
      sid: sessionId,
      tenant_id: null,
    })
    if (completed.kind !== 'redirect') throw new Error(`expected a redirect, got ${completed.kind}`)
    const tokens = await redeem(completed.url)
    if ('error' in tokens) throw new Error(tokens.error)
    expect(claims(tokens.id_token).get('auth_time')).toBe(AUTH_AT_SECONDS)
  })

  it('reports the last factor, not the moment the code was minted, on the path with consent on record', async () => {
    const asked = await authorize()
    if (asked.kind !== 'consent_required') throw new Error(`expected consent_required, got ${asked.kind}`)
    await op.completeConsent({
      client_id: 'app',
      code_challenge: CHALLENGE,
      code_challenge_method: 'S256',
      identity,
      redirect_uri: REDIRECT,
      scope: SCOPE,
      sid: sessionId,
      tenant_id: null,
    })

    const again = await authorize()
    if (again.kind !== 'redirect') throw new Error(`expected a redirect, got ${again.kind}`)
    const tokens = await redeem(again.url)
    if ('error' in tokens) throw new Error(tokens.error)
    const c = claims(tokens.id_token)
    expect(c.get('auth_time')).toBe(AUTH_AT_SECONDS)
    expect(c.get('sid')).toBe(sessionId)
    // The claim is the sign-in, so it has to be older than the token that reports it.
    expect(c.get('iat')).not.toBe(AUTH_AT_SECONDS)
  })

  it('keeps both claims across a refresh rather than reporting the refresh as a sign-in', async () => {
    const asked = await authorize()
    if (asked.kind !== 'consent_required') throw new Error(`expected consent_required, got ${asked.kind}`)
    const completed = await op.completeConsent({
      auth_time: asked.auth_time,
      client_id: 'app',
      code_challenge: CHALLENGE,
      code_challenge_method: 'S256',
      identity,
      redirect_uri: REDIRECT,
      scope: SCOPE,
      sid: sessionId,
      tenant_id: null,
    })
    if (completed.kind !== 'redirect') throw new Error(`expected a redirect, got ${completed.kind}`)
    const first = await redeem(completed.url)
    if ('error' in first) throw new Error(first.error)

    const second = await refresh(first.refresh_token)
    if ('error' in second) throw new Error(second.error)
    expect(claims(second.id_token).get('auth_time')).toBe(AUTH_AT_SECONDS)
    expect(claims(second.id_token).get('sid')).toBe(sessionId)
    // Two rotations out, since each refresh reads the claims off the row it just consumed.
    const third = await refresh(second.refresh_token)
    if ('error' in third) throw new Error(third.error)
    expect(claims(third.id_token).get('auth_time')).toBe(AUTH_AT_SECONDS)
    expect(claims(third.id_token).get('sid')).toBe(sessionId)
  })

  it('omits both claims rather than inventing them when the host measured neither', async () => {
    const completed = await op.completeConsent({
      client_id: 'app',
      code_challenge: CHALLENGE,
      code_challenge_method: 'S256',
      identity,
      redirect_uri: REDIRECT,
      scope: SCOPE,
      sid: '',
      tenant_id: null,
    })
    if (completed.kind !== 'redirect') throw new Error(`expected a redirect, got ${completed.kind}`)
    const first = await redeem(completed.url)
    if ('error' in first) throw new Error(first.error)
    const c = claims(first.id_token)
    expect(c.has('auth_time')).toBe(false)
    expect(c.has('sid')).toBe(false)
    expect(c.get('sub')).toBe(identity.id)

    const second = await refresh(first.refresh_token)
    if ('error' in second) throw new Error(second.error)
    expect(claims(second.id_token).has('auth_time')).toBe(false)
    expect(claims(second.id_token).has('sid')).toBe(false)
  })
})
