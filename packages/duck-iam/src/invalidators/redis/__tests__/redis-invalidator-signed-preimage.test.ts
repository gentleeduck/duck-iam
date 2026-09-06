import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { IamEngineTypes } from '../../../core/engine/engine.types'
import { createIamRedisInvalidator, type IamRedisInvalidator } from '../index'

/**
 * The signature is computed over the publisher's in-memory value but verified
 * against the value that survived the wire's JSON round-trip. Any JSON-lossy
 * construct makes the two pre-images differ and the message is dropped as
 * unverifiable. `cache.invalidateRoles()` with no argument publishes exactly
 * that shape - `{kind: 'roles', roleId: undefined}` - so a blanket role revoke
 * silently stopped propagating the moment signing was turned on.
 */
function makeSharedBus(): IamRedisInvalidator.IPubSubLike {
  const handlers: ((m: string) => void)[] = []
  return {
    publish(_channel, message) {
      for (const h of handlers) h(message)
    },
    subscribe(_channel, h) {
      handlers.push(h)
    },
    unsubscribe() {},
  }
}

async function roundTrip(event: IamEngineTypes.IInvalidateEvent, secret?: string): Promise<unknown[]> {
  const client = makeSharedBus()
  const publisher = createIamRedisInvalidator({ client, secret })
  const receiver = createIamRedisInvalidator({ client, secret })
  const seen: unknown[] = []
  await receiver.subscribe((ev) => {
    seen.push(ev)
  })
  publisher.publish(event)
  return seen
}

describe('signed Redis invalidator pre-image', () => {
  // Silences the drop warning only. Nothing here asserts on it: `warnDropOnce`
  // dedupes per channel at module scope, so whether a given drop warns depends
  // on which test ran first. Delivery is the signal.
  let warnSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
  })

  afterEach(() => {
    warnSpy.mockRestore()
  })

  it('delivers a blanket role invalidation when signing is enabled', async () => {
    expect(await roundTrip({ kind: 'roles', roleId: undefined }, 'shared-secret')).toEqual([{ kind: 'roles' }])
  })

  // Turning signing on must not change which messages arrive - unsigned mode
  // always delivered this one, so "secure" and "correct" disagreeing is itself
  // the defect.
  it('delivers the same event unsigned', async () => {
    expect(await roundTrip({ kind: 'roles', roleId: undefined })).toEqual([{ kind: 'roles' }])
  })

  it('still delivers an event with every field populated', async () => {
    expect(await roundTrip({ kind: 'roles', roleId: 'editor' }, 'shared-secret')).toEqual([
      { kind: 'roles', roleId: 'editor' },
    ])
  })

  it('still rejects a message signed with a different secret', async () => {
    const client = makeSharedBus()
    const publisher = createIamRedisInvalidator({ client, secret: 'one-secret' })
    const receiver = createIamRedisInvalidator({ client, secret: 'another-secret' })
    const seen: unknown[] = []
    await receiver.subscribe((ev) => {
      seen.push(ev)
    })
    publisher.publish({ kind: 'roles', roleId: 'editor' })
    expect(seen).toEqual([])
  })
})
