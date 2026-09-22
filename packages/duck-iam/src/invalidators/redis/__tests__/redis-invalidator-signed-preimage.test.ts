import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { IamEngineTypes } from '../../../core/engine/engine.types'
import { createIamRedisInvalidator, type IamRedisInvalidator } from '../index'

// Signing covers the JSON round-tripped value, so a JSON-lossy event such as `{ kind: 'roles', roleId: undefined }`
// (a blanket role revoke) still verifies.

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
  // Silence only: drop warnings coalesce per channel at module scope, so delivery is the signal, not the warning.
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

  // Turning signing on must not change which messages arrive.
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
