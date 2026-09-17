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
    it('a key with no tenant cannot mint a token for a tenant the caller names', async () => {
      // This was a finding: the cross-tenant guard in `exchange` only fires when
      // the credential itself carries a tenant, so a global key left
      // `verified.tenantId` undefined, the check was skipped, and the `tid` claim
      // was chosen by the request body - the one thing a client_credentials grant
      // must never let a client pick.
      //
      // It is closed at the store instead of the facet. Credential lookups are
      // tenant-scoped, and a global row is not visible to a scoped caller on any
      // dialect, so naming a tenant the key does not belong to no longer resolves
      // the key at all.
      await expect(env.m2m.exchange({ clientId, clientSecret, tenantId: 'victim-tenant' })).rejects.toMatchObject({
        code: 'AUTH_APIKEY_INVALID',
      })
    })

    it('the same global key still works when the caller names no tenant', async () => {
      // Without this the refusal above could pass by breaking global keys outright.
      const result = await env.m2m.exchange({ clientId, clientSecret })
      expect(claims(result.access_token).tid).toBeUndefined()
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

    it('an empty-string tenant is a distinct tenant, not an absent one - and now fails closed', async () => {
      // `!== undefined` is still the only absence test, so `tenantId: ''` is
      // carried as a real tenant rather than collapsing to "unscoped". That used
      // to mint a token; with lookups tenant-scoped it refuses, because no
      // credential belongs to the tenant named by the empty string.
      await expect(env.m2m.exchange({ clientId, clientSecret, tenantId: '' })).rejects.toMatchObject({
        code: 'AUTH_APIKEY_INVALID',
      })
    })
  })

  describe('the scopes the token carries', () => {
    it('refuses rather than minting a token with no scope at all', async () => {
      // RFC 6749 section 3.3 gives the server two answers, fail or issue what it will grant. An
      // empty intersection used to take a third: a token whose scope claim is the empty string,
      // leaving the resource server to decide what a scopeless bearer token means.
      await expect(env.m2m.exchange({ clientId, clientSecret, scope: 'admin:everything' })).rejects.toMatchObject({
        code: 'AUTH_APIKEY_SCOPE_INSUFFICIENT',
      })
    })

    it('still grants the part of a partly-held request that the key does hold', async () => {
      // The refusal above must not become "all or nothing"; that is strict mode's job.
      const result = await env.m2m.exchange({ clientId, clientSecret, scope: 'read:users admin:everything' })
      expect(result.scope).toBe('read:users')
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

    it('the refusal names back only what the caller asked for, never the key’s other scopes', async () => {
      const strict = build({ scopeMode: 'strict', ttlMs: 60_000 })
      const ident = await strict.adapter.identities.create(
        identityInput({ profile: { email: 's@a.test', username: 's@a.test' }, providers: [] }),
      )
      const key = await strict.auth.apiKeys.create(ident.id, { name: 'k', scopes: ['secret:a', 'secret:b'] })
      const err = await strict.m2m
        .exchange({ clientId: key.key.id, clientSecret: key.plaintext, scope: 'nope' })
        .catch((e: AuthError) => e)

      expect((err as AuthError).meta).toEqual({ missing: ['nope'], required: ['nope'] })
      // The meta is not redacted, so anything in it reaches the wire; nothing in it is the key's.
      expect(JSON.stringify((err as AuthError).toJSON())).not.toContain('secret:')
    })

    it('omitting scope grants everything the key holds', async () => {
      const result = await env.m2m.exchange({ clientId, clientSecret })
      expect(result.scope.split(' ').sort()).toEqual(['read:orders', 'read:users', 'write:users'])
    })

    it('a scope string naming nothing is a request, not an absence', async () => {
      // A truthiness test read `scope=` as "omitted" and handed back the full set, so a client
      // asking for nothing received everything the key holds.
      for (const scope of ['', '   \t  ']) {
        await expect(env.m2m.exchange({ clientId, clientSecret, scope })).rejects.toMatchObject({
          code: 'AUTH_INVALID_CREDENTIALS',
        })
      }
    })

    it('deduplicates before counting the cap, so padding cannot push out a real scope', async () => {
      const result = await env.m2m.exchange({ clientId, clientSecret, scope: 'read:users read:users read:users' })
      expect(result.scope).toBe('read:users')

      // Sixty-four copies of one scope used to exhaust the budget and refuse the request outright,
      // taking the scope that followed them down with it.
      const padded = [...Array.from({ length: 64 }, () => 'read:users'), 'write:users'].join(' ')
      expect((await env.m2m.exchange({ clientId, clientSecret, scope: padded })).scope).toBe('read:users write:users')
    })

    it('refuses a scope outside the RFC 6749 grammar, at the key and at the grant', async () => {
      // A quote or a backslash rode into the `scope` claim and back out to whatever parses the
      // token response, where a space-delimited string stops being unambiguous.
      for (const scope of ['read:"users"', 'a\\b', '{"admin":true}']) {
        await expect(makeKey([scope])).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
        await expect(env.m2m.exchange({ clientId, clientSecret, scope })).rejects.toMatchObject({
          code: 'AUTH_INVALID_CREDENTIALS',
        })
      }
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
      // Sixty-four distinct tokens, since the cap counts what survives deduplication.
      const sixtyFour = ['read:users', ...Array.from({ length: 63 }, (_, i) => `s${i}`)].join(' ')
      await expect(env.m2m.exchange({ clientId, clientSecret, scope: sixtyFour })).resolves.toBeDefined()
    })

    it('refuses a non-string scope from an untyped caller', async () => {
      await expect(env.m2m.exchange({ clientId, clientSecret, scope: { a: 1 } as never })).rejects.toMatchObject({
        code: 'AUTH_INVALID_CREDENTIALS',
      })
    })

    it('a key holding no scopes mints an authentication-only token, deliberately', async () => {
      // Left as it is. A service account that proves who it is and carries no authorization is a
      // real shape, and the ambiguity the empty intersection had is absent here: the client asked
      // for nothing, so nothing is what it is told it got.
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

    it('a token minted before revocation keeps verifying afterwards, which is what stateless means', async () => {
      // Left as it is, and documented on the facet. Revoking a leaked key stops new exchanges and
      // does nothing about tokens already issued, for up to the configured ttl. Closing it means
      // a jti denylist or an introspection hop, which is the deployment's call and not a default
      // this library can take on every verify.
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
    it('every exchange still writes a row, and every row now expires with its own token', async () => {
      // One row per call is inherent: nothing about a client_credentials exchange lets the grant
      // reuse an earlier session. What is not inherent is the row outliving the token, which made
      // the growth unbounded - no client ever signs out of an m2m session, so an over-long expiry
      // was a row nothing would ever remove.
      const short = build({ scopeMode: 'intersect', ttlMs: 60_000 })
      const ident = await short.adapter.identities.create(
        identityInput({ profile: { email: 's@a.test', username: 's@a.test' }, providers: [] }),
      )
      const key = await short.auth.apiKeys.create(ident.id, { name: 'k', scopes: ['read:users'] })
      for (let i = 0; i < 25; i++) await short.m2m.exchange({ clientId: key.key.id, clientSecret: key.plaintext })

      const rows = await short.adapter.sessions.listByIdentity(ident.id)
      expect(rows).toHaveLength(25)
      for (const row of rows) expect(row.expiresAt.getTime()).toBeLessThanOrEqual(Date.now() + 60_000)
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

    it('refuses a ttl that could only mint an unusable token, at construction', async () => {
      // An unvalidated `ttlMs` put the expiry in the past, so the grant answered two hundred with a
      // token no resource server would accept and a negative `expires_in` for the client to reason
      // about. Refused where the mistake is, rather than on every exchange after it.
      for (const ttlMs of [-60_000, 0, 999, Number.NaN, Number.POSITIVE_INFINITY, 31 * 24 * 60 * 60 * 1000]) {
        expect(() => build({ scopeMode: 'intersect', ttlMs })).toThrow(
          expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
        )
      }
    })

    it('a ttl longer than the session policy still yields the shorter one, and says so', async () => {
      // The clamp is a `Math.min` and stays one: the sessions facet's ttl (seven days by default) is
      // a ceiling the grant does not get to raise. What changed is that `expires_in` is read back
      // off the session rather than recomputed from the configured ttl, which overstated a lifetime
      // already cut short. A silent transport is what exposes it - JwtTransport clamps its own
      // `expires_in` to the same session expiry, so it never let the wrong number through.
      const silent = {
        clear: () => [],
        issue: () => [{ body: { access_token: 'tok' }, type: 'json' as const }],
        read: async () => null,
        verify: async () => null,
      }
      const fortnight = 14 * 24 * 60 * 60 * 1000
      const facet = new M2MImpl(env.auth.apiKeys, env.auth.sessions, silent as never, {
        scopeMode: 'intersect',
        ttlMs: fortnight,
      })
      const result = await facet.exchange({ clientId, clientSecret })

      expect(result.expires_in).toBeLessThan(fortnight / 1000)
      // Tracks the row rather than the config. Read a moment later than the exchange computed it,
      // so it is the row's remaining seconds or a second or two more, never fewer.
      const [row] = await env.adapter.sessions.listByIdentity(identityId)
      const remaining = Math.floor(((row?.expiresAt.getTime() ?? 0) - Date.now()) / 1000)
      expect(result.expires_in).toBeGreaterThanOrEqual(remaining)
      expect(result.expires_in).toBeLessThanOrEqual(remaining + 2)
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

    it('a transport may shorten the advertised lifetime but never extend it past the policy', async () => {
      // The envelope preferred whatever the transport put in the body, so the number the client was
      // told could disagree with both the operator's ttl and the token's own exp.
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
      expect((await facet.exchange({ clientId, clientSecret })).expires_in).toBeLessThanOrEqual(60)

      const brief = {
        clear: () => [],
        issue: () => [{ body: { access_token: 'tok', expires_in: 5 }, type: 'json' as const }],
        read: async () => null,
        verify: async () => null,
      }
      const short = new M2MImpl(env.auth.apiKeys, env.auth.sessions, brief as never, {
        scopeMode: 'intersect',
        ttlMs: 60_000,
      })
      expect((await short.exchange({ clientId, clientSecret })).expires_in).toBe(5)
    })

    it('a misconfigured transport leaves no session behind', async () => {
      // The AUTH_MISCONFIGURED throw is after `sessions.create`, because only issuing reveals the
      // transport is wrong. Every rejected exchange used to persist a session no token was ever
      // issued for, which a service retrying on the error turns into a row per attempt.
      const cookieish = {
        clear: () => [],
        issue: () => [{ name: 'sid', type: 'cookie' as const, value: 'x' }],
        read: async () => null,
        verify: async () => null,
      }
      const facet = new M2MImpl(env.auth.apiKeys, env.auth.sessions, cookieish as never)
      await facet.exchange({ clientId, clientSecret }).catch(() => undefined)
      expect(await env.adapter.sessions.listByIdentity(identityId)).toHaveLength(0)

      const bodyless = {
        clear: () => [],
        issue: () => [{ body: { ok: true }, type: 'json' as const }],
        read: async () => null,
        verify: async () => null,
      }
      const second = new M2MImpl(env.auth.apiKeys, env.auth.sessions, bodyless as never)
      await second.exchange({ clientId, clientSecret }).catch(() => undefined)
      expect(await env.adapter.sessions.listByIdentity(identityId)).toHaveLength(0)
    })
  })
})
