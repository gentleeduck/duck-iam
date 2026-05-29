/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { MemoryLimiter } from '../../../limiters/memory'
import { AuthRoot } from '../../auth'
import { ScryptHasher } from '../../password/scrypt'
import { JwtTransport } from '../../transport/jwt'
import { M2MFacet } from '../m2m'

interface MyProfile {
  email: string
}

function build() {
  const adapter = new MemoryAuthAdapter<MyProfile>()
  const transport = new JwtTransport({
    signKey: { kid: 'k1', key: 'secret-32-bytes-of-test-material' },
    verifyKeys: [{ kid: 'k1', key: 'secret-32-bytes-of-test-material' }],
    issuer: 'https://app.test',
    ttlMs: 60 * 60 * 1000,
  })
  const auth = new AuthRoot<MyProfile>({
    baseUrl: 'https://app.test',
    transport,
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
    passwords: { hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) },
  })
  const m2m = new M2MFacet(auth.apiKeys, auth.sessions, auth.transport)
  return { auth, adapter, transport, m2m }
}

describe('M2MFacet - client_credentials grant', () => {
  let env: ReturnType<typeof build>
  let clientId: string
  let clientSecret: string
  let identityId: string

  beforeEach(async () => {
    env = build()
    const ident = await env.adapter.identities.create({ profile: { email: 'svc@app.test' }, providers: [] }, {})
    identityId = ident.id
    const created = await env.auth.apiKeys.create(ident.id, {
      name: 'ci-runner',
      scopes: ['read:users', 'write:users', 'read:orders'],
    })
    clientId = created.key.id
    clientSecret = created.plaintext
  })

  it('exchange returns a JWT access_token + token_type + expires_in + scope', async () => {
    const result = await env.m2m.exchange({ clientId, clientSecret })
    expect(result.token_type).toBe('Bearer')
    expect(result.access_token.split('.').length).toBe(3)
    expect(result.expires_in).toBeGreaterThan(0)
    expect(result.scope).toContain('read:users')
  })

  it('access_token verifies via the JwtTransport (round-trip)', async () => {
    const result = await env.m2m.exchange({ clientId, clientSecret })
    const session = await env.transport.verify(result.access_token)
    expect(session).not.toBeNull()
    expect(session!.kind).toBe('apikey')
    expect(session!.identityId).toBe(identityId)
  })

  it('intersect mode: requested scope narrowed to (requested ∩ have)', async () => {
    const result = await env.m2m.exchange({
      clientId,
      clientSecret,
      scope: 'read:users admin:everything',
    })
    expect(result.scope.split(' ').sort()).toEqual(['read:users'])
  })

  it('strict mode: requested scope superset triggers SCOPE_INSUFFICIENT', async () => {
    const strict = new M2MFacet(env.auth.apiKeys, env.auth.sessions, env.transport, {
      ttlMs: 60 * 60 * 1000,
      scopeMode: 'strict',
    })
    await expect(
      strict.exchange({ clientId, clientSecret, scope: 'read:users admin:everything' }),
    ).rejects.toMatchObject({ code: 'AUTH/APIKEY_SCOPE_INSUFFICIENT' })
  })

  it('wrong client_secret throws AUTH/APIKEY_INVALID', async () => {
    await expect(env.m2m.exchange({ clientId, clientSecret: 'not-the-real-secret' })).rejects.toMatchObject({
      code: 'AUTH/APIKEY_INVALID',
    })
  })

  it('mismatched (client_id, secret) pair throws AUTH/APIKEY_INVALID', async () => {
    const other = await env.auth.apiKeys.create(identityId, { name: 'other', scopes: [] })
    await expect(env.m2m.exchange({ clientId: other.key.id, clientSecret })).rejects.toMatchObject({
      code: 'AUTH/APIKEY_INVALID',
    })
  })

  it('missing client_id or client_secret throws AUTH/APIKEY_INVALID', async () => {
    await expect(env.m2m.exchange({ clientId: '', clientSecret })).rejects.toMatchObject({
      code: 'AUTH/APIKEY_INVALID',
    })
    await expect(env.m2m.exchange({ clientId, clientSecret: '' })).rejects.toMatchObject({
      code: 'AUTH/APIKEY_INVALID',
    })
  })

  it('revoked api key rejects with AUTH/APIKEY_REVOKED', async () => {
    await env.auth.apiKeys.revoke(clientId)
    await expect(env.m2m.exchange({ clientId, clientSecret })).rejects.toMatchObject({
      code: 'AUTH/APIKEY_REVOKED',
    })
  })

  it('omitted scope returns the full key scope set', async () => {
    const result = await env.m2m.exchange({ clientId, clientSecret })
    const scopes = result.scope.split(' ').sort()
    expect(scopes).toEqual(['read:orders', 'read:users', 'write:users'])
  })
})
