/**
 * `complete` caps the password it will accept before handing it to the hasher, and that cap has to be
 * the one `set` validated against. They are configurable together as `maxLength`, and the entry point
 * carried the default as a literal instead - so raising the setting produced passwords that could be
 * set and never used again.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256, timingSafeEqual } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import type { Identities } from '~/core/identities'
import { MemoryLimiter } from '~/limiters/memory'
import { ScryptHasher } from '../hashers/scrypt'
import { passwordsImpl } from '../passwords'

interface ProfileShape extends Identities.ProfileMetadataBase {}

const fastHasher = new ScryptHasher({ N: 1 << 10, keylen: 32 })

describe('the sign-in cap follows maxLength', () => {
  let adapter: MemoryAdapter<ProfileShape>
  let ctx: Record<string, unknown>

  beforeEach(async () => {
    adapter = new MemoryAdapter<ProfileShape>()
    await adapter.identities.create({ profile: { email: 'alice@x.com', username: 'alice' }, providers: [] } as never)
    ctx = {
      baseUrl: 'https://x',
      crypto: { authRandomToken: randomToken, authSha256: sha256, authTimingSafeEqual: timingSafeEqual },
      events: new InMemoryEvents(),
      limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      tenant: {},
    }
  })

  it('signs in with a password longer than the default, when the setting allows it', async () => {
    // Set and sign-in read the same number or an operator who raises it locks people out of the
    // passwords they were allowed to choose.
    const provider = passwordsImpl({ hasher: fastHasher, maxLength: 2048 })
    const identity = await adapter.identities.find({ email: 'alice@x.com' })
    if (!identity) throw new Error('expected the seeded identity')
    const long = 'x'.repeat(1500)
    await provider.set(identity.id, long, adapter.credentials)

    await expect(provider.complete(ctx as never, { email: 'alice@x.com', password: long })).resolves.toMatchObject([
      { identityId: identity.id, type: 'startSession' },
    ])
  })

  it('still refuses one past the default when the setting is left alone', async () => {
    const provider = passwordsImpl({ hasher: fastHasher })
    await expect(
      provider.complete(ctx as never, { email: 'alice@x.com', password: 'x'.repeat(1025) }),
    ).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
  })

  it('refuses one past a lowered setting', async () => {
    const provider = passwordsImpl({ hasher: fastHasher, maxLength: 64 })
    await expect(
      provider.complete(ctx as never, { email: 'alice@x.com', password: 'x'.repeat(65) }),
    ).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
  })
})
