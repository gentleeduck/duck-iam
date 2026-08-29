/**
 * Maintenance and read-only are the switches an operator throws when something
 * is already wrong, which is the worst moment to discover that a route slipped
 * through. `assertOperationsForRoute` is the whole enforcement surface, and it
 * decides on two things a caller passes in: an HTTP method string and an exempt
 * flag. Both are pinned here.
 *
 * The existing suite covers the toggles and the precedence between the two
 * modes. These cover the exemption, the method classification, and what is and
 * is not propagated to the rest of a fleet.
 */
import { describe, expect, it } from 'vitest'
import { InMemoryEvents } from '~/core/events'
import { OperationsImpl } from '../operations'

function makeOps() {
  const events = new InMemoryEvents()
  const emitted: Array<{ name: string; payload: unknown }> = []
  for (const name of ['maintenance.on', 'maintenance.off'] as const) {
    events.on(name, (payload) => {
      emitted.push({ name, payload })
    })
  }
  return { emitted, ops: new OperationsImpl(events) }
}

describe('the exemption flag', () => {
  it('FINDING: an exempt route skips read-only as well as maintenance, whatever its method', async () => {
    // The two flags are named `healthz` and `session`, and the guard returns
    // before either mode is consulted. A route marked exempt so it can answer
    // during maintenance, which is the point of the flag, is also the route that
    // keeps accepting writes during a read-only freeze.
    const { ops } = makeOps()
    await ops.readOnly(true)
    expect(() => ops.assertOperationsForRoute('DELETE', { session: true })).not.toThrow()
    expect(() => ops.assertOperationsForRoute('POST', { healthz: true })).not.toThrow()
  })

  it('FINDING: either flag exempts, so passing both by mistake is indistinguishable from either', async () => {
    const { ops } = makeOps()
    await ops.maintenance(true)
    expect(() => ops.assertOperationsForRoute('POST', { healthz: false, session: true })).not.toThrow()
  })

  it('a route with no exemption is blocked in maintenance', async () => {
    const { ops } = makeOps()
    await ops.maintenance(true)
    expect(() => ops.assertOperationsForRoute('GET')).toThrow()
  })

  it('an absent exempt object is the same as no exemption', async () => {
    const { ops } = makeOps()
    await ops.maintenance(true)
    expect(() => ops.assertOperationsForRoute('GET', {})).toThrow()
  })
})

describe('what counts as a mutation', () => {
  it('blocks the four methods it knows about', async () => {
    const { ops } = makeOps()
    await ops.readOnly(true)
    for (const m of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      expect(() => ops.assertOperationsForRoute(m)).toThrow()
    }
  })

  it('lets the safe methods through', async () => {
    const { ops } = makeOps()
    await ops.readOnly(true)
    for (const m of ['GET', 'HEAD', 'OPTIONS']) {
      expect(() => ops.assertOperationsForRoute(m)).not.toThrow()
    }
  })

  it('matches the method case-insensitively', async () => {
    const { ops } = makeOps()
    await ops.readOnly(true)
    expect(() => ops.assertOperationsForRoute('post')).toThrow()
    expect(() => ops.assertOperationsForRoute('DeLeTe')).toThrow()
  })

  it('FINDING: any method outside the four is treated as a read', async () => {
    // The classifier is an allow-list of writes rather than a deny-list of reads,
    // so anything it has not heard of passes. WebDAV and the newer HTTP methods
    // all mutate.
    const { ops } = makeOps()
    await ops.readOnly(true)
    for (const m of ['MKCOL', 'MOVE', 'COPY', 'PROPPATCH', 'LOCK', 'QUERY']) {
      expect(() => ops.assertOperationsForRoute(m)).not.toThrow()
    }
  })

  it('FINDING: read-only classifies by method, so a mutating GET callback is let through', async () => {
    // Magic-link redemption and an OAuth callback are both GETs that consume a
    // one-time credential and create a session. During a migration freeze they
    // keep writing.
    const { ops } = makeOps()
    await ops.readOnly(true)
    expect(() => ops.assertOperationsForRoute('GET')).not.toThrow()
  })

  it('FINDING: a missing method throws a TypeError rather than failing closed', async () => {
    // `method.toUpperCase()` is reached whenever read-only is on. An adapter that
    // does not supply the method produces a raw TypeError, which no error handler
    // in this library maps to a status, so a freeze turns into a five hundred.
    const { ops } = makeOps()
    await ops.readOnly(true)
    expect(() => ops.assertOperationsForRoute(undefined as never)).toThrow(TypeError)
  })

  it('the same missing method is harmless while maintenance is on, because that check comes first', async () => {
    const { ops } = makeOps()
    await ops.maintenance(true)
    await ops.readOnly(true)
    expect(() => ops.assertOperationsForRoute(undefined as never)).toThrow(
      expect.objectContaining({ code: 'AUTH_MAINTENANCE' }),
    )
  })
})

describe('the retry hint an operator supplies', () => {
  it('defaults to sixty seconds', async () => {
    const { ops } = makeOps()
    await ops.maintenance(true)
    expect(() => ops.assertOperationsForRoute('GET')).toThrow(expect.objectContaining({ meta: { retryAfter: 60 } }))
  })

  it('FINDING: a negative or non-finite retry hint is stored and handed to the client', async () => {
    // Nothing validates the value. `Retry-After` is defined as a non-negative
    // number of seconds, so a negative one, or a NaN that serialises to null, is
    // a header a client cannot act on.
    const { ops } = makeOps()
    await ops.maintenance(true, { retryAfterSec: -30 })
    expect(() => ops.assertOperationsForRoute('GET')).toThrow(expect.objectContaining({ meta: { retryAfter: -30 } }))

    await ops.maintenance(true, { retryAfterSec: Number.NaN })
    const thrown = (() => {
      try {
        ops.assertOperationsForRoute('GET')
      } catch (e) {
        return e as { meta: { retryAfter: number } }
      }
    })()
    expect(Number.isNaN(thrown?.meta.retryAfter)).toBe(true)
  })

  it('FINDING: the operator message is unbounded and reaches the client verbatim', async () => {
    // It is an operator-authored string, but it is copied into the error meta with
    // no length cap and no filtering, and an adapter that puts it in a header
    // rather than a body carries whatever it contains.
    const { ops } = makeOps()
    await ops.maintenance(true, { message: `${'x'.repeat(100_000)}\r\nX-Injected: 1` })
    const thrown = (() => {
      try {
        ops.assertOperationsForRoute('GET')
      } catch (e) {
        return e as { meta: { message: string } }
      }
    })()
    expect(thrown?.meta.message).toContain('\r\nX-Injected: 1')
    expect(thrown?.meta.message.length).toBeGreaterThan(100_000)
  })

  it('omits the message key entirely when none was given', async () => {
    const { ops } = makeOps()
    await ops.maintenance(true)
    expect(() => ops.assertOperationsForRoute('GET')).toThrow(expect.objectContaining({ meta: { retryAfter: 60 } }))
  })
})

describe('propagating a switch across a fleet', () => {
  it('maintenance emits on and off so other instances can follow', async () => {
    const { emitted, ops } = makeOps()
    await ops.maintenance(true, { message: 'migrating', retryAfterSec: 120 })
    await ops.maintenance(false)
    expect(emitted.map((e) => e.name)).toEqual(['maintenance.on', 'maintenance.off'])
    expect(emitted[0]?.payload).toEqual({ message: 'migrating', retryAfter: 120 })
  })

  it('FINDING: read-only emits nothing, so it never leaves the instance it was set on', async () => {
    // Maintenance propagates through the bus and read-only does not. An operator
    // who freezes writes on one node of a fleet has frozen one node, and the
    // snapshot on every other node still reads `off`.
    const { emitted, ops } = makeOps()
    await ops.readOnly(true)
    expect(ops.snapshot().readOnly.on).toBe(true)
    expect(emitted).toHaveLength(0)
  })

  it('FINDING: a subscriber that applies the event re-emits it, so a shared bus loops', async () => {
    // The natural way to consume `maintenance.on` is to call `maintenance(true)`
    // on the local instance, and that call emits again. On an in-process bus this
    // recurses immediately; on a shared bus it is a broadcast storm between nodes.
    const events = new InMemoryEvents()
    const ops = new OperationsImpl(events)
    let depth = 0
    events.on('maintenance.on', async () => {
      if (++depth < 5) await ops.maintenance(true)
    })
    await ops.maintenance(true)
    expect(depth).toBe(5)
  })

  it('FINDING: toggling to the state it is already in emits anyway', async () => {
    const { emitted, ops } = makeOps()
    await ops.maintenance(false)
    await ops.maintenance(false)
    expect(emitted).toHaveLength(2)
  })

  it('FINDING: re-asserting maintenance resets the since stamp of the ongoing window', async () => {
    // Two nodes reporting the same maintenance window disagree about when it
    // started, and a repeated deploy hook rewrites it each time.
    const { ops } = makeOps()
    await ops.maintenance(true)
    const first = ops.snapshot().maintenance.since
    await new Promise((r) => setTimeout(r, 5))
    await ops.maintenance(true)
    expect(ops.snapshot().maintenance.since).toBeGreaterThan(first as number)
  })

  it('FINDING: turning maintenance off drops the message and the retry hint with no way to read them back', async () => {
    const { ops } = makeOps()
    await ops.maintenance(true, { message: 'migrating', retryAfterSec: 120 })
    await ops.maintenance(false)
    expect(ops.snapshot().maintenance).toEqual({ on: false })
  })
})

describe('the state snapshot', () => {
  it('is a copy, so a caller cannot flip a mode by editing it', async () => {
    const { ops } = makeOps()
    const snap = ops.snapshot()
    snap.maintenance.on = true
    expect(ops.snapshot().maintenance.on).toBe(false)
    expect(() => ops.assertOperationsForRoute('POST')).not.toThrow()
  })

  it('starts with both modes off and no timestamps', () => {
    const { ops } = makeOps()
    expect(ops.snapshot()).toEqual({ maintenance: { on: false }, readOnly: { on: false } })
  })

  it('maintenance outranks read-only when both are on', async () => {
    const { ops } = makeOps()
    await ops.maintenance(true)
    await ops.readOnly(true)
    expect(() => ops.assertOperationsForRoute('POST')).toThrow(expect.objectContaining({ code: 'AUTH_MAINTENANCE' }))
  })

  it('FINDING: the state lives only in this process, so a restart clears both switches', async () => {
    // Nothing is persisted. A node that restarts during a maintenance window comes
    // back serving traffic, and a rolling deploy is exactly when the window is
    // most likely to be open.
    const { ops } = makeOps()
    await ops.maintenance(true)
    const fresh = makeOps().ops
    expect(fresh.snapshot().maintenance.on).toBe(false)
  })
})
