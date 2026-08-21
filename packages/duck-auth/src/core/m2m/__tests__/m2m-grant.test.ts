/**
 * The client_credentials grant turns a long-lived api key into a short-lived
 * bearer token, so everything it decides is an authorization decision: whose
 * identity the token speaks for, which tenant it is scoped to, and which scopes
 * it carries. The existing suite covers the happy exchange and the scope caps.
 * These cover the inputs the caller controls that are not the secret.
 *
 * Sources: RFC 6749 sections 3.3 and 4.4 (scope handling and the
 * client_credentials grant), RFC 6750 on bearer token lifetime, and RFC 9700
 * section 2.4 on binding a token to the client that asked for it.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities/identities.types'
import { JwtTransport } from '~/core/transport/jwt.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { apiKeyProvider } from '~/providers/api-key'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { identityInput } from '~/test/store-inputs'
import { M2MImpl } from '../m2m'
import type { M2m } from '../m2m.types'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

function build(cfg?: M2m.Cfg) {
  const adapter = new MemoryAdapter<MyProfile>()
  const transport = new JwtTransport({
    issuer: 'https://app.test',
    signKey: { key: 'secret-32-bytes-of-test-material', kid: 'k1' },
    ttlMs: 60 * 60 * 1000,
    verifyKeys: [{ key: 'secret-32-bytes-of-test-material', kid: 'k1' }],
  })
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.test',
    limiter: new MemoryLimiter({ max: 200, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ keylen: 32, N: 1 << 10 }) }), apiKeyProvider()],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport,
  })
  return { adapter, auth, m2m: new M2MImpl(auth.apiKeys, auth.sessions, auth.transport, cfg), transport }
}

/** Decode the JWT payload without verifying, to read what was minted. */
function claims(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split('.')[1] as string, 'base64url').toString('utf8'))
}

describe('m2m client_credentials', () => {
  let env: ReturnType<typeof build>
  let clientId: string
  let clientSecret: string
  let identityId: string

  async function makeKey(scopes: string[], over: { tenantId?: string } = {}) {
    const created = await env.auth.apiKeys.create(identityId, { name: 'k', scopes }, over)
    return { clientId: created.key.id, clientSecret: created.plaintext }
  }

  beforeEach(async () => {
    env = build()
    const ident = await env.adapter.identities.create(
      identityInput({ profile: { email: 'svc@app.test', username: 'svc@app.test' }, providers: [] }),
    )
    identityId = ident.id
    const key = await makeKey(['read:users', 'write:users', 'read:orders'])
    clientId = key.clientId
    clientSecret = key.clientSecret
  })

  describe('the tenant the token speaks for', () => {
    it('FINDING: a key with no tenant mints a token for whatever tenant the caller names', async () => {
      // The cross-tenant guard only fires when the credential itself carries a
      // tenant. A global key leaves `verified.tenantId` undefined, so the check is
      // skipped and `effectiveTenantId` falls through to the caller's value. The
      // `tid` claim on the resulting JWT is then chosen by the request body, which
      // is the one thing a client_credentials grant must never let a client pick.
      const result = await env.m2m.exchange({ clientId, clientSecret, tenantId: 'victim-tenant' })
      expect(claims(result.access_token).tid).toBe('victim-tenant')
    })

    it('refuses when a tenant-scoped key is asked to mint for a different tenant', async () => {
      const scoped = await makeKey(['read:users'], { tenantId: 'tenant-a' })
      await expect(env.m2m.exchange({ ...scoped, tenantId: 'tenant-b' })).rejects.toMatchObject({
        code: 'AUTH_APIKEY_INVALID',
      })
    })

    it('falls back to the credential’s own tenant when the caller names none', async () => {
      const scoped = await makeKey(['read:users'], { tenantId: 'tenant-a' })
      const result = await env.m2m.exchange(scoped)
      expect(claims(result.access_token).tid).toBe('tenant-a')
    })

    it('FINDING: an empty-string tenant is a distinct tenant, not an absent one', async () => {
      // `!== undefined` is the only absence test, so `tenantId: ''` reaches the
      // session and the claim as a real value.
      const result = await env.m2m.exchange({ clientId, clientSecret, tenantId: '' })
      expect(result.access_token.split('.')).toHaveLength(3)
    })
  })

  describe('the scopes the token carries', () => {
    it('FINDING: asking for scopes the key does not have yields a token with no scope at all', async () => {
      // In the default intersect mode an empty intersection is not an error. RFC
      // 6749 section 3.3 says the server must either fail or issue the scopes it
      // is willing to grant; issuing a token with an empty scope claim leaves the
      // resource server to decide what a scopeless bearer token means, which is
      // exactly the ambiguity that turns into an allow.
      const result = await env.m2m.exchange({ clientId, clientSecret, scope: 'admin:everything' })
      expect(result.scope).toBe('')
      expect(claims(result.access_token).scope).toBe('')
    })

    it('strict mode refuses the same request instead', async () => {
      const strict = build({ scopeMode: 'strict', ttlMs: 60_000 })
      const ident = await strict.adapter.identities.create(
        identityInput({ profile: { email: 's@a.test', username: 's@a.test' }, providers: [] }),
      )
      const key = await strict.auth.apiKeys.create(ident.id, { name: 'k', scopes: ['read:users'] })
      await expect(
        strict.m2m.exchange({ clientId: key.key.id, clientSecret: key.plaintext, scope: 'admin:everything' }),
      ).rejects.toMatchObject({ code: 'AUTH_APIKEY_SCOPE_INSUFFICIENT' })
    })

    it('FINDING: the strict-mode refusal reports the key’s full scope set back to the caller', async () => {
      // The error meta carries `have`, so a caller probing with one scope learns
      // every scope the key holds. The caller already has the secret, but an error
      // body forwarded to a client, or written to a shared log, spreads it.
      const strict = build({ scopeMode: 'strict', ttlMs: 60_000 })
      const ident = await strict.adapter.identities.create(
        identityInput({ profile: { email: 's@a.test', username: 's@a.test' }, providers: [] }),
      )
      const key = await strict.auth.apiKeys.create(ident.id, { name: 'k', scopes: ['secret:a', 'secret:b'] })
      const err = await strict.m2m
        .exchange({ clientId: key.key.id, clientSecret: key.plaintext, scope: 'nope' })
        .catch((e: AuthError) => e)

      expect((err as AuthError).meta.have).toEqual(['secret:a', 'secret:b'])
      // And the redactor does not treat it as sensitive, so it survives onto the wire.
      expect((err as AuthError).toJSON().error).toMatchObject({ have: ['secret:a', 'secret:b'] })
    })

    it('omitting scope grants everything the key holds', async () => {
      const result = await env.m2m.exchange({ clientId, clientSecret })
      expect(result.scope.split(' ').sort()).toEqual(['read:orders', 'read:users', 'write:users'])
    })

    it('FINDING: an empty scope string is read as omitted, so it grants everything', async () => {
      // `if (input.scope)` is a truthiness test, so a client sending `scope=`
      // asking for nothing receives the full set instead of none.
      const result = await env.m2m.exchange({ clientId, clientSecret, scope: '' })
      expect(result.scope.split(' ')).toHaveLength(3)
    })

    it('FINDING: a whitespace-only scope also grants everything', async () => {
      // The split filters out empties, leaving a zero-length request, which
      // `_resolveScopes` treats the same as no request at all.
      const result = await env.m2m.exchange({ clientId, clientSecret, scope: '   \t  ' })
      expect(result.scope.split(' ')).toHaveLength(3)
    })

    it('FINDING: duplicates survive into the granted scope claim and count against the cap', async () => {
      // Nothing deduplicates, so a client can pad the scope string. Sixty-four
      // copies of one scope exhausts the token budget and pushes out the scopes
      // that follow it in the same request.
      const result = await env.m2m.exchange({ clientId, clientSecret, scope: 'read:users read:users read:users' })
      expect(result.scope).toBe('read:users read:users read:users')

      const padded = [...Array.from({ length: 64 }, () => 'read:users'), 'write:users'].join(' ')
      await expect(env.m2m.exchange({ clientId, clientSecret, scope: padded })).rejects.toMatchObject({
        code: 'AUTH_INVALID_CREDENTIALS',
      })
    })

    it('FINDING: a scope token may contain any character that is not whitespace', async () => {
      // RFC 6749 section 3.3 restricts a scope token to a printable subset that
      // excludes the quote and the backslash. Neither the grant nor the key
      // creation path checks, so a quote or a brace rides into the `scope` claim
      // and back out to whatever parses the response.
      const key = await makeKey(['read:"users"', 'a\\b', '{"admin":true}'])
      const result = await env.m2m.exchange(key)
      expect(result.scope).toContain('{"admin":true}')
      expect(claims(result.access_token).scope).toContain('read:"users"')
    })

    it('splits on any run of whitespace, including newlines', async () => {
      const result = await env.m2m.exchange({ clientId, clientSecret, scope: 'read:users\n\twrite:users' })
      expect(result.scope).toBe('read:users write:users')
    })

    it('refuses a scope string past the length cap and a token list past the count cap', async () => {
      await expect(env.m2m.exchange({ clientId, clientSecret, scope: 'x'.repeat(4097) })).rejects.toMatchObject({
        code: 'AUTH_INVALID_CREDENTIALS',
      })
      const many = Array.from({ length: 65 }, (_, i) => `s${i}`).join(' ')
      await expect(env.m2m.exchange({ clientId, clientSecret, scope: many })).rejects.toMatchObject({
        code: 'AUTH_INVALID_CREDENTIALS',
      })
    })

    it('accepts a request sitting exactly on both caps', async () => {
      const sixtyFour = Array.from({ length: 64 }, () => 'read:users').join(' ')
      await expect(env.m2m.exchange({ clientId, clientSecret, scope: sixtyFour })).resolves.toBeDefined()
    })

    it('refuses a non-string scope from an untyped caller', async () => {
      await expect(env.m2m.exchange({ clientId, clientSecret, scope: { a: 1 } as never })).rejects.toMatchObject({
        code: 'AUTH_INVALID_CREDENTIALS',
      })
    })

    it('FINDING: a key holding no scopes still mints a token rather than being refused', async () => {
      const key = await makeKey([])
      const result = await env.m2m.exchange(key)
      expect(result.scope).toBe('')
      expect(result.access_token.split('.')).toHaveLength(3)
    })
  })

  describe('the credential pair', () => {
    it('refuses a valid secret presented under a different client id', async () => {
      const other = await makeKey(['read:users'])
      await expect(env.m2m.exchange({ clientId: other.clientId, clientSecret })).rejects.toMatchObject({
        code: 'AUTH_APIKEY_INVALID',
      })
    })

    it('refuses an empty client id or secret before touching the store', async () => {
      await expect(env.m2m.exchange({ clientId: '', clientSecret })).rejects.toMatchObject({
        code: 'AUTH_APIKEY_INVALID',
      })
      await expect(env.m2m.exchange({ clientId, clientSecret: '' })).rejects.toMatchObject({
        code: 'AUTH_APIKEY_INVALID',
      })
    })

    it('refuses a revoked key', async () => {
      await env.auth.apiKeys.revoke(clientId)
      await expect(env.m2m.exchange({ clientId, clientSecret })).rejects.toMatchObject({
        code: 'AUTH_APIKEY_REVOKED',
      })
    })

    it('FINDING: a token minted before revocation keeps verifying afterwards', async () => {
      // Documented on the facet, pinned here because it is the grant's sharpest
      // edge: revoking a leaked key stops new exchanges and does nothing about the
      // tokens already issued, for up to the configured ttl. The default ttl is an
      // hour.
      const result = await env.m2m.exchange({ clientId, clientSecret })
      await env.auth.apiKeys.revoke(clientId)
      expect(await env.transport.verify(result.access_token)).not.toBeNull()
    })

    it('refuses a secret longer than the hashing cap', async () => {
      await expect(env.m2m.exchange({ clientId, clientSecret: 'x'.repeat(513) })).rejects.toMatchObject({
        code: 'AUTH_APIKEY_INVALID',
      })
    })

    it('a client id differing only in case is refused', async () => {
      await expect(env.m2m.exchange({ clientId: clientId.toUpperCase(), clientSecret })).rejects.toMatchObject({
        code: 'AUTH_APIKEY_INVALID',
      })
    })
  })

  describe('what each exchange leaves behind', () => {
    it('FINDING: every exchange persists a session row that nothing ever cleans up', async () => {
      // The grant is stateless from the client's point of view, but each call
      // writes a session. A service polling for a token, or an attacker holding a
      // valid key, grows the session store one row per request, and the rows are
      // never revoked because no client ever signs out of them.
      for (let i = 0; i < 25; i++) await env.m2m.exchange({ clientId, clientSecret })
      expect(await env.adapter.sessions.listByIdentity(identityId)).toHaveLength(25)
    })

    it('FINDING: the persisted session outlives the token whose lifetime was capped', async () => {
      // `issue` receives a copy with the expiry clamped to the m2m ttl, but the
      // row written a moment earlier keeps the sessions facet's own, longer
      // expiry. The token expires in a minute; the record stays live far past it.
      const short = build({ scopeMode: 'intersect', ttlMs: 60_000 })
      const ident = await short.adapter.identities.create(
        identityInput({ profile: { email: 's@a.test', username: 's@a.test' }, providers: [] }),
      )
      const key = await short.auth.apiKeys.create(ident.id, { name: 'k', scopes: ['read:users'] })
      await short.m2m.exchange({ clientId: key.key.id, clientSecret: key.plaintext })

      const [row] = await short.adapter.sessions.listByIdentity(ident.id)
      expect(row?.expiresAt.getTime()).toBeGreaterThan(Date.now() + 60_000)
    })

    it('the minted session is an apikey session at aal 1, not a user session', async () => {
      await env.m2m.exchange({ clientId, clientSecret })
      const [row] = await env.adapter.sessions.listByIdentity(identityId)
      expect(row).toMatchObject({ aal: 1, kind: 'apikey' })
    })

    it('the token verifies back to the identity that owns the key', async () => {
      const result = await env.m2m.exchange({ clientId, clientSecret })
      const session = await env.transport.verify(result.access_token)
      expect(session?.identityId).toBe(identityId)
    })
  })

  describe('the configured lifetime', () => {
    it('advertises expires_in in seconds, matching the ttl', async () => {
      const short = build({ scopeMode: 'intersect', ttlMs: 120_000 })
      const ident = await short.adapter.identities.create(
        identityInput({ profile: { email: 's@a.test', username: 's@a.test' }, providers: [] }),
      )
      const key = await short.auth.apiKeys.create(ident.id, { name: 'k', scopes: [] })
      const result = await short.m2m.exchange({ clientId: key.key.id, clientSecret: key.plaintext })
      expect(result.expires_in).toBeLessThanOrEqual(120)
    })

    it('FINDING: a negative ttl is accepted and mints a token that is already expired', async () => {
      // Nothing validates `ttlMs`. The clamped expiry lands in the past, so the
      // grant returns a two hundred with a token no resource server will accept,
      // and a negative `expires_in` for the client to reason about.
      const bad = build({ scopeMode: 'intersect', ttlMs: -60_000 })
      const ident = await bad.adapter.identities.create(
        identityInput({ profile: { email: 's@a.test', username: 's@a.test' }, providers: [] }),
      )
      const key = await bad.auth.apiKeys.create(ident.id, { name: 'k', scopes: [] })
      const result = await bad.m2m.exchange({ clientId: key.key.id, clientSecret: key.plaintext })

      expect(result.expires_in).toBeLessThan(0)
      expect(await bad.transport.verify(result.access_token)).toBeNull()
    })

    it('FINDING: a ttl longer than the session lifetime is silently ignored', async () => {
      // The clamp is a `Math.min`, so asking for a twenty-four hour token against a
      // shorter session policy quietly yields the shorter one while `expires_in`
      // is computed from the configured ttl and overstates it.
      const long = build({ scopeMode: 'intersect', ttlMs: 24 * 60 * 60 * 1000 })
      const ident = await long.adapter.identities.create(
        identityInput({ profile: { email: 's@a.test', username: 's@a.test' }, providers: [] }),
      )
      const key = await long.auth.apiKeys.create(ident.id, { name: 'k', scopes: [] })
      const result = await long.m2m.exchange({ clientId: key.key.id, clientSecret: key.plaintext })

      const exp = (claims(result.access_token).exp as number) * 1000
      expect(exp).toBeLessThan(Date.now() + 24 * 60 * 60 * 1000)
      expect(result.expires_in).toBeGreaterThan((exp - Date.now()) / 1000)
    })
  })

  describe('the transport contract', () => {
    it('refuses a transport that emits no json intent', async () => {
      const cookieish = {
        clear: () => [],
        issue: () => [{ name: 'sid', type: 'cookie' as const, value: 'x' }],
        read: async () => null,
        verify: async () => null,
      }
      const facet = new M2MImpl(env.auth.apiKeys, env.auth.sessions, cookieish as never)
      await expect(facet.exchange({ clientId, clientSecret })).rejects.toMatchObject({
        code: 'AUTH_MISCONFIGURED',
      })
    })

    it('refuses a transport whose json body carries no access token', async () => {
      const empty = {
        clear: () => [],
        issue: () => [{ body: { ok: true }, type: 'json' as const }],
        read: async () => null,
        verify: async () => null,
      }
      const facet = new M2MImpl(env.auth.apiKeys, env.auth.sessions, empty as never)
      await expect(facet.exchange({ clientId, clientSecret })).rejects.toMatchObject({
        code: 'AUTH_MISCONFIGURED',
      })
    })

    it('refuses a non-finite expires_in rather than passing NaN to the client', async () => {
      const nan = {
        clear: () => [],
        issue: () => [{ body: { access_token: 'tok', expires_in: Number.NaN }, type: 'json' as const }],
        read: async () => null,
        verify: async () => null,
      }
      const facet = new M2MImpl(env.auth.apiKeys, env.auth.sessions, nan as never)
      await expect(facet.exchange({ clientId, clientSecret })).rejects.toMatchObject({
        code: 'AUTH_MISCONFIGURED',
      })
    })

    it('FINDING: a transport reporting its own expires_in overrides the m2m policy in the response', async () => {
      // The envelope prefers whatever the transport put in the body, so the number
      // the client is told can disagree with the ttl the operator configured, and
      // with the token's actual exp.
      const lying = {
        clear: () => [],
        issue: () => [{ body: { access_token: 'tok', expires_in: 999_999 }, type: 'json' as const }],
        read: async () => null,
        verify: async () => null,
      }
      const facet = new M2MImpl(env.auth.apiKeys, env.auth.sessions, lying as never, {
        scopeMode: 'intersect',
        ttlMs: 60_000,
      })
      expect((await facet.exchange({ clientId, clientSecret })).expires_in).toBe(999_999)
    })

    it('FINDING: the session is written before the transport is checked, so a misconfiguration still leaves rows', async () => {
      // The AUTH_MISCONFIGURED throw happens after `sessions.create`. Every
      // rejected exchange against a wrongly wired transport persists a session
      // that no token was ever issued for.
      const cookieish = {
        clear: () => [],
        issue: () => [{ name: 'sid', type: 'cookie' as const, value: 'x' }],
        read: async () => null,
        verify: async () => null,
      }
      const facet = new M2MImpl(env.auth.apiKeys, env.auth.sessions, cookieish as never)
      await facet.exchange({ clientId, clientSecret }).catch(() => undefined)
      expect(await env.adapter.sessions.listByIdentity(identityId)).toHaveLength(1)
    })
  })
})
