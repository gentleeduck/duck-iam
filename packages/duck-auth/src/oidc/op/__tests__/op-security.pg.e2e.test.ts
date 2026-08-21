/**
 * E2E: the OIDC OP's security invariants, driven through the whole provider with
 * REAL Postgres behind it.
 *
 * `oidc-op.pg.e2e` proves the stores keep their contract. This proves the provider
 * enforces the rules that contract exists to serve, and it does so against a real
 * database because the two interesting ones are both "exactly one row changed"
 * claims: an authorization code must burn on first presentation even when the
 * request is then rejected, and a refresh token reuse must revoke a whole family.
 *
 * The cases come from RFC 9700 (BCP 240, OAuth 2.0 Security Best Current
 * Practice): bind the code to the client and to the redirect_uri, require PKCE for
 * public clients and verify it, rotate refresh tokens and detect reuse.
 *
 * Skips when DUCKAUTH_E2E_DATABASE_URL is unset; `globalSetup` provisions a
 * container when docker is available.
 */
import { Buffer } from 'node:buffer'
import { createHmac, randomUUID } from 'node:crypto'
import { Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { sha256 } from '~/core/crypto'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { isolatedDatabaseUrl } from '~/test/e2e-env'
import { authCreateDrizzlePgOidcOpStores } from '../drizzle/pg'
import { createOidcOP, type OidcOpRoot } from '../index'
import type { OidcOP } from '../types'

const URL = await isolatedDatabaseUrl('oidc_security_pg')
const suite = URL ? describe : describe.skip

interface ProfileShape extends Identities.ProfileMetadataBase {
  name?: string
}

/** RFC 7636 S256: challenge = base64url(sha256(verifier)). */
function pkce(seed: string): { verifier: string; challenge: string } {
  const verifier = seed.padEnd(64, 'x')
  return { challenge: Buffer.from(sha256(verifier), 'hex').toString('base64url'), verifier }
}

const CONFIDENTIAL_SECRET = 'confidential-secret'
const REDIRECT = 'https://app.test/cb'
const OTHER_REDIRECT = 'https://app.test/cb2'

suite('OIDC OP security invariants on real Postgres', () => {
  let pool: Pool
  let op: OidcOpRoot<ProfileShape>
  let stores: ReturnType<typeof authCreateDrizzlePgOidcOpStores>
  let identityId: string

  /** Basic auth header for a confidential client. */
  const clientAuth = (id: string, secret = CONFIDENTIAL_SECRET) =>
    new Headers({ authorization: `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}` })

  beforeAll(async () => {
    pool = new Pool({ connectionString: URL })
    const { readFileSync } = await import('node:fs')
    const { join } = await import('node:path')
    await pool.query(readFileSync(join(process.cwd(), 'src/test/oidc-pg-e2e-schema.sql'), 'utf8'))

    const { drizzle } = await import('drizzle-orm/node-postgres')
    stores = authCreateDrizzlePgOidcOpStores(drizzle(pool) as never)

    const adapter = new MemoryAdapter<ProfileShape>()
    const auth = new AuthEngine<ProfileShape>({
      baseUrl: 'http://localhost:8787',
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'duck-sid' }),
    })
    const identity = await auth.identities.create({ profile: { email: 'op@test.local', username: 'op-user' } })
    identityId = identity.id

    op = createOidcOP<ProfileShape>({
      auth,
      config: {
        allowHttp: true,
        issuer: 'http://localhost:8787/auth',
        supportedScopes: ['openid', 'profile', 'offline_access'],
      },
      signIdToken: (payload) => {
        const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
        const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
        const sig = createHmac('sha256', 'dev-secret').update(`${header}.${body}`).digest('base64url')
        return `${header}.${body}.${sig}`
      },
      stores,
    })
  }, 60_000)

  afterAll(async () => {
    await pool?.end()
  })

  beforeEach(async () => {
    await pool.query('TRUNCATE oidc_consents, oidc_refresh_tokens, oidc_access_tokens, oidc_codes, oidc_clients')
    await op.registerClient({
      client_id: 'app-a',
      client_name: 'App A',
      client_secret: CONFIDENTIAL_SECRET,
      grant_types: ['authorization_code', 'refresh_token'],
      redirect_uris: [REDIRECT, OTHER_REDIRECT],
      scope: ['openid', 'profile', 'offline_access'],
    })
    await op.registerClient({
      client_id: 'app-b',
      client_name: 'App B',
      client_secret: CONFIDENTIAL_SECRET,
      grant_types: ['authorization_code', 'refresh_token'],
      redirect_uris: [REDIRECT],
      scope: ['openid', 'profile'],
    })
  })

  /** Plant a code the way `authorize` would, so the token endpoint is what is under test. */
  async function plantCode(over: Partial<OidcOP.Code> = {}): Promise<string> {
    const code = `code-${randomUUID()}`
    await stores.codes.insert({
      client_id: 'app-a',
      code,
      code_challenge: null,
      code_challenge_method: null,
      exp: Date.now() + 60_000,
      identity_id: identityId,
      nonce: null,
      redirect_uri: REDIRECT,
      scope: ['openid', 'profile'],
      sid: 'sid-1',
      tenant_id: null,
      ...over,
    })
    return code
  }

  describe('the authorization code is bound to its client', () => {
    it('refuses a code issued to another client', async () => {
      // RFC 9700 code injection: app-b presents a code minted for app-a. Without
      // this check, any client that can obtain a code can redeem it as itself.
      const code = await plantCode({ client_id: 'app-a' })
      const res = await op.token(
        { code, grant_type: 'authorization_code', redirect_uri: REDIRECT },
        clientAuth('app-b'),
      )
      expect(res).toMatchObject({ error: 'invalid_grant' })
    })

    it('burns the code even when the client check then rejects it', async () => {
      // The code is consumed before the binding is examined, deliberately: a
      // rejected attempt must not leave the code redeemable by its rightful owner,
      // or an attacker gets a free oracle and the victim still completes login.
      const code = await plantCode({ client_id: 'app-a' })
      await op.token({ code, grant_type: 'authorization_code', redirect_uri: REDIRECT }, clientAuth('app-b'))

      const retry = await op.token(
        { code, grant_type: 'authorization_code', redirect_uri: REDIRECT },
        clientAuth('app-a'),
      )
      expect(retry).toMatchObject({ error: 'invalid_grant' })
      expect(await stores.codes.consume(code, Date.now())).toBeNull()
    })

    it('accepts the code from the client it was issued to', async () => {
      const code = await plantCode({ client_id: 'app-a' })
      const res = await op.token(
        { code, grant_type: 'authorization_code', redirect_uri: REDIRECT },
        clientAuth('app-a'),
      )
      expect(res).toMatchObject({ token_type: 'Bearer' })
    })
  })

  describe('the authorization code is bound to its redirect_uri', () => {
    it('refuses a redirect_uri that differs from the one the code was issued for', async () => {
      // Both URIs are registered to app-a, so this is not a registration check: the
      // code itself has to remember which one was used.
      const code = await plantCode({ redirect_uri: REDIRECT })
      const res = await op.token(
        { code, grant_type: 'authorization_code', redirect_uri: OTHER_REDIRECT },
        clientAuth('app-a'),
      )
      expect(res).toMatchObject({ error: 'invalid_grant' })
    })

    it('requires a redirect_uri at all', async () => {
      const code = await plantCode()
      const res = await op.token({ code, grant_type: 'authorization_code' }, clientAuth('app-a'))
      expect(res).toMatchObject({ error: 'invalid_request' })
    })

    it('matches exactly, not by prefix', async () => {
      const code = await plantCode({ redirect_uri: REDIRECT })
      const res = await op.token(
        { code, grant_type: 'authorization_code', redirect_uri: `${REDIRECT}/../cb` },
        clientAuth('app-a'),
      )
      expect(res).toMatchObject({ error: 'invalid_grant' })
    })
  })

  describe('PKCE', () => {
    it('refuses to redeem a challenged code without a verifier', async () => {
      // Dropping the verifier is the PKCE downgrade: if it is accepted, an
      // intercepted code is redeemable again.
      const { challenge } = pkce('verifier-a')
      const code = await plantCode({ code_challenge: challenge, code_challenge_method: 'S256' })
      const res = await op.token(
        { code, grant_type: 'authorization_code', redirect_uri: REDIRECT },
        clientAuth('app-a'),
      )
      expect(res).toMatchObject({ error: 'invalid_grant' })
    })

    it('refuses a verifier that does not hash to the challenge', async () => {
      const { challenge } = pkce('verifier-a')
      const other = pkce('verifier-b')
      const code = await plantCode({ code_challenge: challenge, code_challenge_method: 'S256' })
      const res = await op.token(
        { code, code_verifier: other.verifier, grant_type: 'authorization_code', redirect_uri: REDIRECT },
        clientAuth('app-a'),
      )
      expect(res).toMatchObject({ error: 'invalid_grant' })
    })

    it('accepts the matching verifier', async () => {
      const { challenge, verifier } = pkce('verifier-a')
      const code = await plantCode({ code_challenge: challenge, code_challenge_method: 'S256' })
      const res = await op.token(
        { code, code_verifier: verifier, grant_type: 'authorization_code', redirect_uri: REDIRECT },
        clientAuth('app-a'),
      )
      expect(res).toMatchObject({ token_type: 'Bearer' })
    })
  })

  describe('code lifetime and replay', () => {
    it('refuses an expired code', async () => {
      const code = await plantCode({ exp: Date.now() - 1 })
      const res = await op.token(
        { code, grant_type: 'authorization_code', redirect_uri: REDIRECT },
        clientAuth('app-a'),
      )
      expect(res).toMatchObject({ error: 'invalid_grant' })
    })

    it('refuses the second redemption of a good code', async () => {
      const code = await plantCode()
      expect(
        await op.token({ code, grant_type: 'authorization_code', redirect_uri: REDIRECT }, clientAuth('app-a')),
      ).toMatchObject({ token_type: 'Bearer' })
      expect(
        await op.token({ code, grant_type: 'authorization_code', redirect_uri: REDIRECT }, clientAuth('app-a')),
      ).toMatchObject({ error: 'invalid_grant' })
    })

    it('admits exactly one of two simultaneous redemptions', async () => {
      // The stolen-code race, through the provider rather than the store.
      const code = await plantCode()
      const [a, b] = await Promise.all([
        op.token({ code, grant_type: 'authorization_code', redirect_uri: REDIRECT }, clientAuth('app-a')),
        op.token({ code, grant_type: 'authorization_code', redirect_uri: REDIRECT }, clientAuth('app-a')),
      ])
      const issued = [a, b].filter((r) => 'token_type' in r)
      expect(issued).toHaveLength(1)
    })
  })

  describe('client authentication', () => {
    it('refuses a wrong client secret', async () => {
      const code = await plantCode()
      const res = await op.token(
        { code, grant_type: 'authorization_code', redirect_uri: REDIRECT },
        clientAuth('app-a', 'wrong-secret'),
      )
      expect(res).toMatchObject({ error: 'invalid_client' })
    })

    it('refuses an unknown client', async () => {
      const code = await plantCode()
      const res = await op.token(
        { code, grant_type: 'authorization_code', redirect_uri: REDIRECT },
        clientAuth('no-such-client'),
      )
      expect(res).toMatchObject({ error: 'invalid_client' })
    })
  })

  describe('refresh token rotation and reuse detection', () => {
    async function issueRefresh(): Promise<{ refresh: string; access: string }> {
      const code = await plantCode({ scope: ['openid', 'offline_access'] })
      const res = await op.token(
        { code, grant_type: 'authorization_code', redirect_uri: REDIRECT },
        clientAuth('app-a'),
      )
      if (!('refresh_token' in res) || typeof res.refresh_token !== 'string') {
        throw new Error(`expected a refresh token, got ${JSON.stringify(res)}`)
      }
      return { access: res.access_token, refresh: res.refresh_token }
    }

    it('rotates: the old refresh token stops working once used', async () => {
      const first = await issueRefresh()
      const rotated = await op.token({ grant_type: 'refresh_token', refresh_token: first.refresh }, clientAuth('app-a'))
      expect(rotated).toMatchObject({ token_type: 'Bearer' })

      const replay = await op.token({ grant_type: 'refresh_token', refresh_token: first.refresh }, clientAuth('app-a'))
      expect(replay).toMatchObject({ error: 'invalid_grant' })
    })

    it('a reuse revokes the whole family, including the token the attacker did not have', async () => {
      // The point of rotation: replaying a consumed token means one of the two
      // holders is an attacker, and the server cannot tell which. Both must lose.
      const first = await issueRefresh()
      const rotated = await op.token({ grant_type: 'refresh_token', refresh_token: first.refresh }, clientAuth('app-a'))
      if (!('refresh_token' in rotated) || typeof rotated.refresh_token !== 'string') {
        throw new Error('expected a rotated refresh token')
      }

      // Attacker replays the consumed one.
      await op.token({ grant_type: 'refresh_token', refresh_token: first.refresh }, clientAuth('app-a'))

      // The legitimate holder's current token must now be dead too.
      const afterRevoke = await op.token(
        { grant_type: 'refresh_token', refresh_token: rotated.refresh_token },
        clientAuth('app-a'),
      )
      expect(afterRevoke).toMatchObject({ error: 'invalid_grant' })
    })

    it('refuses a refresh token presented by a different client', async () => {
      const first = await issueRefresh()
      const res = await op.token({ grant_type: 'refresh_token', refresh_token: first.refresh }, clientAuth('app-b'))
      expect(res).toMatchObject({ error: 'invalid_grant' })
    })

    it('issues no refresh token when offline_access was not granted', async () => {
      const code = await plantCode({ scope: ['openid'] })
      const res = await op.token(
        { code, grant_type: 'authorization_code', redirect_uri: REDIRECT },
        clientAuth('app-a'),
      )
      expect(res).toMatchObject({ token_type: 'Bearer' })
      expect('refresh_token' in res && res.refresh_token).toBeFalsy()
    })
  })

  describe('userinfo', () => {
    it('accepts a freshly issued access token and returns the subject', async () => {
      const code = await plantCode()
      const res = await op.token(
        { code, grant_type: 'authorization_code', redirect_uri: REDIRECT },
        clientAuth('app-a'),
      )
      if (!('access_token' in res)) throw new Error('expected an access token')
      const info = await op.userinfo(new Headers({ authorization: `Bearer ${res.access_token}` }), {})
      expect(info).toMatchObject({ sub: identityId })
    })

    it('refuses a token that was never issued', async () => {
      const info = await op.userinfo(new Headers({ authorization: 'Bearer not-a-real-token' }), {})
      expect(info).toMatchObject({ error: 'invalid_token' })
    })

    it('refuses a missing Authorization header', async () => {
      expect(await op.userinfo(new Headers(), {})).toMatchObject({ error: 'invalid_token' })
    })
  })
})
