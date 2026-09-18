/**
 * `exchange()` is the `client_credentials` grant: it compares a caller-supplied secret against stored
 * material and mints a bearer token on a match. `ApiKeyProvider.complete` does the same comparison
 * through the same `ApiKeysFacet.verify` and guards it twice — a type-and-length check so a non-string
 * cannot throw past the quota, then `limiter.consume`. This path had neither.
 */

import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { M2MImpl as CoreM2MImpl, m2m as coreM2m, DEFAULT_M2M_CONFIG } from '~/core'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { JwtTransport } from '~/core/transport/jwt.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { apiKeyProvider } from '~/providers/api-key'
import { identityInput } from '~/test/store-inputs'
import { M2MImpl } from '../m2m'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

const KEY = 'secret-32-bytes-of-test-material'

let seq = 0

function build(max: number) {
  const adapter = new MemoryAdapter<MyProfile>()
  const transport = new JwtTransport({
    issuer: 'https://app.test',
    signKey: { key: KEY, kid: 'k1' },
    ttlMs: 60 * 60 * 1000,
    verifyKeys: [{ key: KEY, kid: 'k1' }],
  })
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.test',
    limiter: new MemoryLimiter({ max: 200, windowMs: 60_000 }),
    providers: [apiKeyProvider()],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport,
  })
  const limiter = new MemoryLimiter({ max, windowMs: 60_000 })
  return { adapter, auth, limiter, m2m: new M2MImpl(auth.apiKeys, auth.sessions, auth.transport, limiter) }
}

describe('the client_credentials grant is bounded', () => {
  let env: ReturnType<typeof build>
  let clientId: string
  let clientSecret: string

  async function newKey(): Promise<{ clientId: string; clientSecret: string }> {
    const who = `svc${seq++}`
    const ident = await env.adapter.identities.create(
      identityInput({ profile: { email: `${who}@app.test`, username: who }, providers: [] }),
    )
    const created = await env.auth.apiKeys.create(ident.id, { name: 'k', scopes: ['read:users'] })
    return { clientId: created.key.id, clientSecret: created.plaintext }
  }

  beforeEach(async () => {
    env = build(3)
    const k = await newKey()
    clientId = k.clientId
    clientSecret = k.clientSecret
  })

  it('refuses with AUTH_RATE_LIMITED once the budget for a client is spent', async () => {
    for (let i = 0; i < 3; i++) {
      await expect(env.m2m.exchange({ clientId, clientSecret: 'wrong' })).rejects.toMatchObject({
        code: 'AUTH_APIKEY_INVALID',
      })
    }
    await expect(env.m2m.exchange({ clientId, clientSecret: 'wrong' })).rejects.toMatchObject({
      code: 'AUTH_RATE_LIMITED',
    })
  })

  it('bounds a guessing run, where a per-secret key would hand every guess a fresh budget', async () => {
    // The load-bearing case: every attempt presents a *different* secret, which is what a brute force
    // looks like. Keyed on the secret, as the api-key path is, this run never exhausts anything.
    for (let i = 0; i < 3; i++) {
      await expect(env.m2m.exchange({ clientId, clientSecret: `guess-${i}` })).rejects.toMatchObject({
        code: 'AUTH_APIKEY_INVALID',
      })
    }
    await expect(env.m2m.exchange({ clientId, clientSecret: 'guess-3' })).rejects.toMatchObject({
      code: 'AUTH_RATE_LIMITED',
    })
  })

  it('refuses the correct secret too once the budget is gone, so the quota runs before the compare', async () => {
    for (let i = 0; i < 3; i++) {
      await expect(env.m2m.exchange({ clientId, clientSecret: `guess-${i}` })).rejects.toBeDefined()
    }
    await expect(env.m2m.exchange({ clientId, clientSecret })).rejects.toMatchObject({
      code: 'AUTH_RATE_LIMITED',
    })
  })

  it('spends one client budget, not the whole endpoint', async () => {
    const other = await newKey()
    for (let i = 0; i < 4; i++) {
      await expect(env.m2m.exchange({ clientId, clientSecret: `guess-${i}` })).rejects.toBeDefined()
    }

    const ok = await env.m2m.exchange({ clientId: other.clientId, clientSecret: other.clientSecret })
    expect(ok.access_token).toBeTruthy()
  })
})

describe('the inputs reach the hash and the limiter key as strings or not at all', () => {
  let env: ReturnType<typeof build>

  beforeEach(() => {
    env = build(3)
  })

  it('refuses a non-string secret rather than throwing a TypeError out of sha256', async () => {
    // Untyped, this reached `authSha256` and threw: a 500 from a path whose refusal is a 401, and the
    // throw happened before anything was counted.
    const hostile = { clientId: 'c', clientSecret: { toString: () => 'x' } } as unknown as {
      clientId: string
      clientSecret: string
    }
    await expect(env.m2m.exchange(hostile)).rejects.toMatchObject({ code: 'AUTH_APIKEY_INVALID' })
  })

  it('refuses an over-long clientId without spending the budget it would have keyed', async () => {
    const huge = 'a'.repeat(513)
    for (let i = 0; i < 5; i++) {
      await expect(env.m2m.exchange({ clientId: huge, clientSecret: 'x' })).rejects.toMatchObject({
        code: 'AUTH_APIKEY_INVALID',
      })
    }

    // Five refusals and the budget of three is untouched, because the cap fires above the limiter.
    const still = await env.limiter.consume('m2m:' + huge)
    expect(still.remaining).toBe(2)
  })

  it('refuses an over-long secret, which is a sha256 input before it is anything else', async () => {
    await expect(env.m2m.exchange({ clientId: 'c', clientSecret: 'b'.repeat(513) })).rejects.toMatchObject({
      code: 'AUTH_APIKEY_INVALID',
    })
  })
})

describe('the grant is reachable from outside the package', () => {
  it('exports the implementation, not only its type namespace', () => {
    // `./core` exported `type { M2m }` and nothing else, so a host could name `M2m.ExchangeInput` and
    // had no way to obtain anything that accepts one. The class docstring tells them to mount a route
    // calling `exchange()`.
    expect(CoreM2MImpl).toBe(M2MImpl)
    expect(typeof coreM2m).toBe('function')
    expect(DEFAULT_M2M_CONFIG.ttlMs).toBeGreaterThan(0)
  })
})
