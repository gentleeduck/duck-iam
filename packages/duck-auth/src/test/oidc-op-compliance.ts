/**
 * Shared contract for the OIDC OP stores, so every dialect answers the same
 * questions instead of each restating them.
 *
 * Only the sqlite flavour had a test, and it is bun-gated, so under Node nothing
 * exercised these stores at all and the pg and mysql flavours were never run.
 * That matters more here than in most stores: single-use codes and refresh-token
 * rotation are the security properties of an authorization server, and both are
 * "delete/mark returned exactly one row" claims that only a real database can
 * settle. The sqlite DDL also drops the constraints, so the shipped schemas were
 * unproven even where the suite did run.
 *
 * @param factory - fresh, empty stores per case. Callers wipe between cases.
 */
import { describe, expect, it } from 'vitest'
import type { OidcOP } from '~/oidc/op/types'

export type OidcOpStores = {
  clients: OidcOP.ClientStore
  codes: OidcOP.CodeStore
  accessTokens: OidcOP.AccessTokenStore
  refreshTokens: OidcOP.RefreshTokenStore
  consents: OidcOP.ConsentStore
}

export function runOidcOpCompliance(factory: () => OidcOpStores): void {
  const client = (over: Partial<OidcOP.Client> = {}): OidcOP.Client => ({
    client_id: 'app',
    client_name: 'Test App',
    client_secret_hash: 'hash',
    createdAt: 1_700_000_000,
    grant_types: ['authorization_code', 'refresh_token'],
    redirect_uris: ['https://app.test/cb'],
    response_types: ['code'],
    scope: ['openid', 'profile'],
    token_endpoint_auth_method: 'client_secret_basic',
    ...over,
  })

  const code = (over: Partial<OidcOP.Code> = {}): OidcOP.Code => ({
    client_id: 'app',
    code: 'code-1',
    code_challenge: null,
    code_challenge_method: null,
    exp: Date.now() + 60_000,
    identity_id: 'user-1',
    nonce: null,
    redirect_uri: 'https://app.test/cb',
    scope: ['openid'],
    sid: 'sid-1',
    tenant_id: null,
    ...over,
  })

  const accessToken = (over: Partial<OidcOP.AccessToken> = {}): OidcOP.AccessToken => ({
    client_id: 'app',
    exp: Date.now() + 60_000,
    identity_id: 'user-1',
    scope: ['openid'],
    tenant_id: null,
    token_hash: 'at-1',
    ...over,
  })

  const refreshToken = (over: Partial<OidcOP.RefreshToken> = {}): OidcOP.RefreshToken => ({
    client_id: 'app',
    consumedAt: null,
    exp: Date.now() + 60_000,
    family_id: 'family-1',
    identity_id: 'user-1',
    scope: ['openid', 'offline_access'],
    tenant_id: null,
    token_hash: 'rt-1',
    ...over,
  })

  describe('OIDC OP store compliance', () => {
    describe('clients', () => {
      it('round-trips a client, arrays included', async () => {
        const s = factory()
        await s.clients.insert(client())
        const found = await s.clients.findById('app')
        expect(found?.client_id).toBe('app')
        expect(found?.redirect_uris).toEqual(['https://app.test/cb'])
        expect(found?.grant_types).toEqual(['authorization_code', 'refresh_token'])
        expect(found?.scope).toEqual(['openid', 'profile'])
        expect(found?.client_name).toBe('Test App')
      })

      it('returns null for an unknown client', async () => {
        expect(await factory().clients.findById('nope')).toBeNull()
      })

      it('keeps a public client with no secret distinguishable from one with a secret', async () => {
        // token_endpoint_auth_method 'none' plus a null hash is how a public client
        // is stored; collapsing null to '' would let it authenticate as confidential.
        const s = factory()
        await s.clients.insert(
          client({ client_id: 'public-app', client_secret_hash: null, token_endpoint_auth_method: 'none' }),
        )
        const found = await s.clients.findById('public-app')
        expect(found?.client_secret_hash).toBeNull()
        expect(found?.token_endpoint_auth_method).toBe('none')
      })

      it('preserves multiple redirect uris in order', async () => {
        const s = factory()
        const uris = ['https://app.test/cb', 'https://app.test/cb2', 'myapp://callback']
        await s.clients.insert(client({ redirect_uris: uris }))
        expect((await s.clients.findById('app'))?.redirect_uris).toEqual(uris)
      })
    })

    describe('authorization codes', () => {
      it('consume returns the code once and never again', async () => {
        // Single use is the entire security property. A second success here is an
        // authorization code replay.
        const s = factory()
        await s.codes.insert(code())
        expect((await s.codes.consume('code-1', Date.now()))?.code).toBe('code-1')
        expect(await s.codes.consume('code-1', Date.now())).toBeNull()
      })

      it('admits exactly one of many simultaneous consumes', async () => {
        // Two token requests racing on a stolen code. Only a real database can say
        // whether the delete-and-return is atomic.
        const s = factory()
        await s.codes.insert(code({ code: 'race' }))
        const now = Date.now()
        const results = await Promise.all(Array.from({ length: 10 }, () => s.codes.consume('race', now)))
        expect(results.filter(Boolean)).toHaveLength(1)
      })

      it('refuses an expired code', async () => {
        const s = factory()
        await s.codes.insert(code({ code: 'stale', exp: Date.now() - 1 }))
        expect(await s.codes.consume('stale', Date.now())).toBeNull()
      })

      it('returns null for a code that never existed', async () => {
        expect(await factory().codes.consume('never', Date.now())).toBeNull()
      })

      it('carries the PKCE challenge back to the token endpoint', async () => {
        // Losing these silently downgrades PKCE to no PKCE.
        const s = factory()
        await s.codes.insert(
          code({ code: 'pkce', code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256' }),
        )
        const consumed = await s.codes.consume('pkce', Date.now())
        expect(consumed?.code_challenge).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
        expect(consumed?.code_challenge_method).toBe('S256')
      })

      it('carries nonce and sid back, since the id token depends on both', async () => {
        const s = factory()
        await s.codes.insert(code({ code: 'nonce', nonce: 'n-abc', sid: 'session-xyz' }))
        const consumed = await s.codes.consume('nonce', Date.now())
        expect(consumed?.nonce).toBe('n-abc')
        expect(consumed?.sid).toBe('session-xyz')
      })

      it('consuming one code leaves the others alone', async () => {
        const s = factory()
        await s.codes.insert(code({ code: 'keep-a' }))
        await s.codes.insert(code({ code: 'keep-b' }))
        await s.codes.consume('keep-a', Date.now())
        expect(await s.codes.consume('keep-b', Date.now())).not.toBeNull()
      })
    })

    describe('access tokens', () => {
      it('insert, find, revoke', async () => {
        const s = factory()
        await s.accessTokens.insert(accessToken())
        expect((await s.accessTokens.findByHash('at-1', Date.now()))?.identity_id).toBe('user-1')
        await s.accessTokens.revokeByHash('at-1')
        expect(await s.accessTokens.findByHash('at-1', Date.now())).toBeNull()
      })

      it('an expired token does not read back', async () => {
        const s = factory()
        await s.accessTokens.insert(accessToken({ exp: Date.now() - 1, token_hash: 'at-old' }))
        expect(await s.accessTokens.findByHash('at-old', Date.now())).toBeNull()
      })

      it('revoking one token leaves the others alone', async () => {
        const s = factory()
        await s.accessTokens.insert(accessToken({ token_hash: 'at-a' }))
        await s.accessTokens.insert(accessToken({ token_hash: 'at-b' }))
        await s.accessTokens.revokeByHash('at-a')
        expect(await s.accessTokens.findByHash('at-b', Date.now())).not.toBeNull()
      })

      it('preserves the granted scope', async () => {
        const s = factory()
        await s.accessTokens.insert(accessToken({ scope: ['openid', 'profile', 'email'], token_hash: 'at-scope' }))
        expect((await s.accessTokens.findByHash('at-scope', Date.now()))?.scope).toEqual([
          'openid',
          'profile',
          'email',
        ])
      })
    })

    describe('refresh tokens', () => {
      it('consume returns the token once and never again', async () => {
        const s = factory()
        await s.refreshTokens.insert(refreshToken())
        expect((await s.refreshTokens.consume('rt-1', Date.now()))?.token_hash).toBe('rt-1')
        expect(await s.refreshTokens.consume('rt-1', Date.now())).toBeNull()
      })

      it('admits exactly one of many simultaneous consumes', async () => {
        // Rotation detection rests on this: a second winner is a reuse that the
        // server would not notice.
        const s = factory()
        await s.refreshTokens.insert(refreshToken({ token_hash: 'rt-race' }))
        const now = Date.now()
        const results = await Promise.all(Array.from({ length: 10 }, () => s.refreshTokens.consume('rt-race', now)))
        expect(results.filter(Boolean)).toHaveLength(1)
      })

      it('revokeFamily kills every token in the family and spares the rest', async () => {
        // The response to a detected reuse: the whole lineage goes, and another
        // user's session must not.
        const s = factory()
        await s.refreshTokens.insert(refreshToken({ token_hash: 'fam-a' }))
        await s.refreshTokens.insert(refreshToken({ token_hash: 'fam-b' }))
        await s.refreshTokens.insert(refreshToken({ family_id: 'family-2', token_hash: 'other' }))

        await s.refreshTokens.revokeFamily('family-1')

        expect(await s.refreshTokens.findByHash('fam-a', Date.now())).toBeNull()
        expect(await s.refreshTokens.findByHash('fam-b', Date.now())).toBeNull()
        expect(await s.refreshTokens.findByHash('other', Date.now())).not.toBeNull()
      })

      it('an expired refresh token does not read back', async () => {
        const s = factory()
        await s.refreshTokens.insert(refreshToken({ exp: Date.now() - 1, token_hash: 'rt-old' }))
        expect(await s.refreshTokens.findByHash('rt-old', Date.now())).toBeNull()
      })

      it('keeps the family id, which is what a reuse revokes by', async () => {
        const s = factory()
        await s.refreshTokens.insert(refreshToken({ family_id: 'lineage-9', token_hash: 'rt-fam' }))
        expect((await s.refreshTokens.findByHash('rt-fam', Date.now()))?.family_id).toBe('lineage-9')
      })
    })

    describe('consents', () => {
      it('upsert replaces the scope rather than adding a row', async () => {
        const s = factory()
        await s.consents.upsert({ client_id: 'app', grantedAt: 1, identity_id: 'user-1', scope: ['openid'] })
        expect((await s.consents.find('user-1', 'app'))?.scope).toEqual(['openid'])

        await s.consents.upsert({ client_id: 'app', grantedAt: 2, identity_id: 'user-1', scope: ['openid', 'email'] })
        const row = await s.consents.find('user-1', 'app')
        expect(row?.scope).toEqual(['openid', 'email'])
        expect(row?.grantedAt).toBe(2)
      })

      it('separates consent per (identity, client) pair', async () => {
        const s = factory()
        await s.consents.upsert({ client_id: 'app', grantedAt: 1, identity_id: 'user-a', scope: ['openid'] })
        await s.consents.upsert({ client_id: 'app', grantedAt: 1, identity_id: 'user-b', scope: ['openid', 'email'] })
        await s.consents.upsert({ client_id: 'other', grantedAt: 1, identity_id: 'user-a', scope: ['profile'] })

        expect((await s.consents.find('user-a', 'app'))?.scope).toEqual(['openid'])
        expect((await s.consents.find('user-b', 'app'))?.scope).toEqual(['openid', 'email'])
        expect((await s.consents.find('user-a', 'other'))?.scope).toEqual(['profile'])
      })

      it('returns null when no consent was ever granted', async () => {
        expect(await factory().consents.find('nobody', 'app')).toBeNull()
      })
    })
  })
}
