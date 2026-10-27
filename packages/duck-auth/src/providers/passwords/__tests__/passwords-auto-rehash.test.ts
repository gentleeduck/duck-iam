/**
 * `autoRehash` is how a hashing-parameter upgrade reaches people: `verify` reports that the stored hash
 * came from weaker params, and the sign-in re-hashes under the current ones in the background. It is on
 * by default and, before this file, had no test anywhere in the package.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import type { Credential } from '~/core/credentials/credentials.types'
import { randomToken, sha256, timingSafeEqual } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import type { Identities } from '~/core/identities'
import { MemoryLimiter } from '~/limiters/memory'
import type { Hasher } from '../hashers/hashers.types'
import { passwordsImpl } from '../passwords'

interface ProfileShape extends Identities.ProfileMetadataBase {}

/** Writes land a tick later, as a driver's round trip does. */
function deferredWrites(base: Credential.Store): Credential.Store {
  return {
    ...base,
    rotate: async (...args: Parameters<Credential.Store['rotate']>) => {
      await new Promise((resolve) => setTimeout(resolve, 0))
      return base.rotate(...args)
    },
  }
}

/** Stands in for a parameter upgrade: anything not carrying the new prefix wants rehashing, and hashing
 *  costs real time, which is the window the two writes race inside. */
const upgradedHasher: Hasher.Me = {
  id: 'stub-v2',
  hash: async (plaintext: string) => {
    await new Promise((resolve) => setTimeout(resolve, 15))
    return `v2:${plaintext}`
  },
  needsRehash: (encoded: string) => !encoded.startsWith('v2:'),
  verify: async () => true,
}

describe('autoRehash rolls a parameter upgrade out on sign-in', () => {
  let adapter: MemoryAdapter<ProfileShape>
  let identityId: string
  let ctx: {
    baseUrl: string
    crypto: {
      authRandomToken: typeof randomToken
      authSha256: typeof sha256
      authTimingSafeEqual: typeof timingSafeEqual
    }
    events: InMemoryEvents
    limiter: MemoryLimiter
    stores: {
      credentials: Credential.Store
      identities: MemoryAdapter<ProfileShape>['identities']
      sessions: MemoryAdapter<ProfileShape>['sessions']
    }
    tenant: Record<string, never>
  }

  beforeEach(async () => {
    adapter = new MemoryAdapter<ProfileShape>()
    const identity = await adapter.identities.create({
      emailVerified: false,
      profile: { email: 'alice@x.com', username: 'alice' },
      providers: [],
    })
    identityId = identity.id
    await adapter.credentials.create(
      {
        expiresAt: null,
        identityId,
        kind: 'password',
        lastUsedAt: null,
        metadata: { algorithm: 'stub-v1' },
        revokedAt: null,
        secret: 'v1:correct-horse-battery',
        tenantId: null,
      },
      {},
    )
    ctx = {
      baseUrl: 'https://x',
      crypto: { authRandomToken: randomToken, authSha256: sha256, authTimingSafeEqual: timingSafeEqual },
      events: new InMemoryEvents(),
      limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
      stores: {
        credentials: deferredWrites(adapter.credentials),
        identities: adapter.identities,
        sessions: adapter.sessions,
      },
      tenant: {},
    }
  })

  const storedSecret = async (): Promise<string | undefined> => {
    const rows = await adapter.credentials.listByIdentity(identityId, 'password', {})
    return rows[0]?.secret
  }

  it('replaces the stored hash after a sign-in that reported needsRehash', async () => {
    const provider = passwordsImpl({ hasher: upgradedHasher })
    await provider.complete(ctx, { email: 'alice@x.com', password: 'correct-horse-battery' })

    await vi.waitFor(
      async () => {
        if ((await storedSecret()) !== 'v2:correct-horse-battery') {
          throw new Error(`still on the old hash: ${await storedSecret()}`)
        }
      },
      { interval: 5, timeout: 1000 },
    )
  })

  it('leaves the hash alone when the stored one is already current', async () => {
    const provider = passwordsImpl({ hasher: upgradedHasher })
    await adapter.credentials.deleteByKind(identityId, 'password', {})
    await adapter.credentials.create(
      {
        expiresAt: null,
        identityId,
        kind: 'password',
        lastUsedAt: null,
        metadata: { algorithm: 'stub-v2' },
        revokedAt: null,
        secret: 'v2:correct-horse-battery',
        tenantId: null,
      },
      {},
    )
    await provider.complete(ctx, { email: 'alice@x.com', password: 'correct-horse-battery' })
    await new Promise((resolve) => setTimeout(resolve, 60))

    expect(await storedSecret()).toBe('v2:correct-horse-battery')
  })

  it('does not rehash when the option is off', async () => {
    const provider = passwordsImpl({ autoRehash: false, hasher: upgradedHasher })
    await provider.complete(ctx, { email: 'alice@x.com', password: 'correct-horse-battery' })
    await new Promise((resolve) => setTimeout(resolve, 60))

    expect(await storedSecret()).toBe('v1:correct-horse-battery')
  })
})

describe('a rehash racing a password change', () => {
  /** Hashes carry their generation and the password. `hold` makes the next `hash` wait until released, so a
   *  reset can land inside it while its own hash runs free. */
  function gatedHasher() {
    let generation = 1
    let gate = Promise.resolve()
    const hasher: Hasher.Me = {
      id: 'gated',
      hash: async (plaintext: string) => {
        const at = generation
        const wait = gate
        gate = Promise.resolve()
        await wait
        return `v${at}:${plaintext}`
      },
      needsRehash: (encoded: string) => !encoded.startsWith(`v${generation}:`),
      verify: async (plaintext: string, encoded: string) => encoded.slice(encoded.indexOf(':') + 1) === plaintext,
    }
    return {
      hasher,
      hold: () => {
        let release = () => {}
        gate = new Promise<void>((resolve) => {
          release = resolve
        })
        return release
      },
      upgrade: () => {
        generation += 1
      },
    }
  }

  it('does not put back the password a reset replaced while it was hashing', async () => {
    const adapter = new MemoryAdapter<ProfileShape>()
    const { id } = await adapter.identities.create({
      emailVerified: false,
      profile: { email: 'alice@x.com', username: 'alice' },
      providers: [],
    })
    const gated = gatedHasher()
    const facet = passwordsImpl({ hasher: gated.hasher, minLength: 1, rejectCommon: false })
    await facet.set(id, 'old-password', adapter.credentials, null)
    gated.upgrade()
    expect(await facet.verify(id, 'old-password', adapter.credentials)).toEqual({ needsRehash: true, ok: true })

    const release = gated.hold()
    const rehash = facet.rehash(id, 'old-password', adapter.credentials)
    await facet.set(id, 'new-password', adapter.credentials, null)
    release()
    await rehash

    expect((await facet.verify(id, 'new-password', adapter.credentials)).ok).toBe(true)
    expect((await facet.verify(id, 'old-password', adapter.credentials)).ok).toBe(false)
  })
})
