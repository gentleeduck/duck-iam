import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { IamEngineTypes } from '../../../core/engine/engine.types'
import { createIamRedisInvalidator, type IamRedisInvalidator } from '../index'

/**
 * The signed receive path, which the existing suite exercises almost entirely
 * through `{ kind: 'all' }` - the one event shape with no optional properties.
 *
 *     $ grep -oh "kind: '[a-z]*'" src/invalidators/redis/__tests__/*.ts | sort | uniq -c
 *       21 kind: 'all'   3 kind: 'policies'   3 kind: 'roles'   6 kind: 'subject'
 *
 * so 34 tests passed while the signed path was broken for two of the four
 * kinds. The rest of this file covers the guards a mutation run found unpinned:
 * the whole guard band of the HMAC comparator (a `return true` on its length
 * check is a complete signature bypass and killed no test), `_isValidEvent` on
 * the *signed* branch, the replay-window boundary, and the pre-auth wire cap's
 * byte-length semantics.
 */

function makeBus(): {
  client: IamRedisInvalidator.IPubSubLike
  deliver: (msg: string) => void
  published: string[]
} {
  let handler: ((m: string) => void) | null = null
  const published: string[] = []
  return {
    client: {
      publish(_channel, message) {
        published.push(message)
      },
      subscribe(_channel, h) {
        handler = h
      },
      unsubscribe() {
        return undefined
      },
    },
    deliver(msg) {
      handler?.(msg)
    },
    published,
  }
}

const SECRET = 'shared-secret'

/** A publisher and a subscriber on the same channel, sharing a secret. */
function pair() {
  const a = makeBus()
  const b = makeBus()
  const channel = `t-${Math.random().toString(36).slice(2)}`
  const publisher = createIamRedisInvalidator({ channel, client: a.client, secret: SECRET })
  const received: IamEngineTypes.IInvalidateEvent[] = []
  createIamRedisInvalidator({ channel, client: b.client, secret: SECRET }).subscribe((e) => received.push(e))
  return { a, b, publisher, received }
}

/**
 * Builds an event the way a tampered wire message carries one - as parsed JSON.
 * `publish` signs whatever it is handed and does not validate, which is exactly
 * how a validly-signed invalid event reaches the receiver's own guard.
 */
function asEvent(json: string): IamEngineTypes.IInvalidateEvent {
  return JSON.parse(json)
}

let warnSpy: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
})

afterEach(() => {
  warnSpy.mockRestore()
})

describe('a signed round-trip carries every event kind', () => {
  const CASES: ReadonlyArray<{
    expected: IamEngineTypes.IInvalidateEvent
    name: string
    sent: IamEngineTypes.IInvalidateEvent
  }> = [
    { expected: { kind: 'all' }, name: 'all', sent: { kind: 'all' } },
    { expected: { kind: 'policies' }, name: 'policies', sent: { kind: 'policies' } },
    { expected: { kind: 'roles' }, name: 'roles with roleId omitted', sent: { kind: 'roles' } },
    // `cache.invalidateRoles()` with no argument publishes exactly this shape.
    // The signing pre-image JSON-round-trips first, so the key disappears on
    // both sides; signing the live object made publisher and verifier hash
    // different byte strings and a blanket role revoke never propagated.
    { expected: { kind: 'roles' }, name: 'roles with roleId: undefined', sent: { kind: 'roles', roleId: undefined } },
    {
      expected: { kind: 'roles', roleId: 'editor' },
      name: 'roles with a roleId',
      sent: { kind: 'roles', roleId: 'editor' },
    },
    { expected: { kind: 'subject', subjectId: 'u1' }, name: 'subject', sent: { kind: 'subject', subjectId: 'u1' } },
  ]

  for (const { expected, name, sent } of CASES) {
    it(`${name} verifies and dispatches`, () => {
      const { a, b, publisher, received } = pair()
      publisher.publish(sent)
      b.deliver(a.published[0] ?? '')
      expect(received).toEqual([expected])
    })
  }
})

describe('the HMAC comparator rejects every malformed signature', () => {
  /** A valid signed wire message, with `sig` replaced. */
  function withSig(replace: (sig: string) => string): { deliveredCount: number } {
    const { a, b, publisher, received } = pair()
    publisher.publish({ kind: 'all' })
    const envelope = JSON.parse(a.published[0] ?? '')
    const sig: unknown = Reflect.get(envelope, 'sig')
    if (typeof sig !== 'string') throw new Error('published envelope carries no string sig')
    b.deliver(JSON.stringify({ ...envelope, sig: replace(sig) }))
    return { deliveredCount: received.length }
  }

  // Control first: without it every assertion below passes for a harness that
  // simply never delivers anything.
  it('delivers the untouched envelope', () => {
    expect(withSig((sig) => sig).deliveredCount).toBe(1)
  })

  const REJECTED: ReadonlyArray<{ name: string; replace: (sig: string) => string }> = [
    // The length pre-check. A mutant turning it into `return true` accepts any
    // wrong-length signature - `sig: "00"` verifies - and killed no test.
    { name: 'a truncated signature', replace: (sig) => sig.slice(0, -2) },
    { name: 'an over-long signature', replace: (sig) => `${sig}00` },
    { name: 'a two-character signature', replace: () => '00' },
    // The empty-buffer check: `Buffer.from('', 'hex')` is zero-length on both
    // sides, and `timingSafeEqual` calls two empty buffers equal.
    { name: 'an empty signature', replace: () => '' },
    // Non-hex of the right *string* length. `Buffer.from` stops at the first
    // invalid pair, so this decodes to an empty buffer too.
    { name: 'a same-length non-hex signature', replace: (sig) => 'z'.repeat(sig.length) },
    { name: 'a flipped nibble', replace: (sig) => (sig.startsWith('0') ? `1${sig.slice(1)}` : `0${sig.slice(1)}`) },
  ]

  for (const { name, replace } of REJECTED) {
    it(`drops ${name}`, () => {
      expect(withSig(replace).deliveredCount).toBe(0)
    })
  }
})

describe('a valid signature is not a valid event', () => {
  // `_isValidEvent`'s own doc says it exists "so a tampered payload cannot
  // trigger an invalidate with an undefined `subjectId`". On the signed branch
  // that guarantee had no test: forcing the check to `if (false)` killed
  // nothing, because every signed test published a well-formed event.
  const MALFORMED = [
    '{"kind":"subject"}',
    '{"kind":"subject","subjectId":""}',
    '{"kind":"subject","subjectId":123}',
    '{"kind":"roles","roleId":""}',
    '{"kind":"roles","roleId":7}',
    '{"kind":"nope"}',
    '{}',
    'null',
    '[1,2]',
    '"all"',
    '7',
  ]

  for (const json of MALFORMED) {
    it(`drops a correctly signed ${json}`, () => {
      const { a, b, publisher, received } = pair()
      publisher.publish(asEvent(json))
      b.deliver(a.published[0] ?? '')
      expect(received).toEqual([])
    })
  }

  it('still delivers the well-formed neighbour of those', () => {
    const { a, b, publisher, received } = pair()
    publisher.publish(asEvent('{"kind":"subject","subjectId":"u1"}'))
    b.deliver(a.published[0] ?? '')
    expect(received).toEqual([{ kind: 'subject', subjectId: 'u1' }])
  })
})

describe('the replay window is closed at its stated edge', () => {
  const WINDOW_MS = 30_000
  const T0 = 1_770_000_000_000

  afterEach(() => {
    vi.useRealTimers()
  })

  /** Publishes at `T0`, delivers `offset` ms later. */
  function deliverAfter(offset: number): number {
    vi.useFakeTimers()
    vi.setSystemTime(T0)
    const { a, b, publisher, received } = pair()
    publisher.publish({ kind: 'all' })
    vi.setSystemTime(T0 + offset)
    b.deliver(a.published[0] ?? '')
    return received.length
  }

  // `age > WINDOW` vs `age >= WINDOW` is one character and no test could tell
  // them apart.
  it('accepts a message exactly at the window edge', () => {
    expect(deliverAfter(WINDOW_MS)).toBe(1)
  })

  it('drops a message one millisecond past the edge', () => {
    expect(deliverAfter(WINDOW_MS + 1)).toBe(0)
  })

  // The other side of the same check: a message from a clock running ahead.
  it('accepts a message exactly at the future edge', () => {
    expect(deliverAfter(-WINDOW_MS)).toBe(1)
  })

  it('drops a message one millisecond beyond the future edge', () => {
    expect(deliverAfter(-WINDOW_MS - 1)).toBe(0)
  })
})

describe('the pre-auth wire cap counts bytes, not code units', () => {
  const MAX_WIRE_BYTES = 16 * 1024

  /** Delivers a signed message whose subject id is `count` copies of `char`. */
  function deliverPadded(char: string, count: number): { bytes: number; delivered: number; units: number } {
    const { a, b, publisher, received } = pair()
    publisher.publish({ kind: 'subject', subjectId: char.repeat(count) })
    const wire = a.published[0] ?? ''
    b.deliver(wire)
    return { bytes: Buffer.byteLength(wire, 'utf8'), delivered: received.length, units: wire.length }
  }

  it('drops a message under the cap in characters but over it in bytes', () => {
    // '€' is three UTF-8 bytes and one UTF-16 code unit, so `s.length` reads
    // this as comfortably inside the cap while it is not.
    const out = deliverPadded('€', 6000)
    expect(out.units).toBeLessThan(MAX_WIRE_BYTES)
    expect(out.bytes).toBeGreaterThan(MAX_WIRE_BYTES)
    expect(out.delivered).toBe(0)
  })

  it('delivers a multi-byte message that fits', () => {
    const out = deliverPadded('€', 1000)
    expect(out.bytes).toBeLessThan(MAX_WIRE_BYTES)
    expect(out.delivered).toBe(1)
  })

  // Control on the ASCII side, so the cap is pinned in the units it declares.
  it('drops an ASCII message past the cap and delivers one just inside it', () => {
    expect(deliverPadded('a', MAX_WIRE_BYTES).delivered).toBe(0)
    expect(deliverPadded('a', 1000).delivered).toBe(1)
  })
})
