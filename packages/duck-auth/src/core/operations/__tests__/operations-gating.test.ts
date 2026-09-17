/**
 * Maintenance and read-only are the switches an operator throws when something
 * is already wrong, which is the worst moment to discover that a route slipped
 * through. `assertOperationsForRoute` is the whole enforcement surface, and it
 * decides on two things a caller passes in: an HTTP method string and an exempt
 * flag. Both are pinned here.
 */
import { describe, expect, it } from 'vitest'
import { AuthError } from '~/core/errors'
import { InMemoryEvents } from '~/core/events'
import { OperationsImpl } from '../operations'
import type { Operations } from '../operations.types'

function makeOps() {
  const events = new InMemoryEvents()
  const emitted: Array<{ name: string; payload: unknown }> = []
  for (const name of ['maintenance.on', 'maintenance.off', 'readonly.on', 'readonly.off'] as const) {
    events.on(name, (payload) => {
      emitted.push({ name, payload })
    })
  }
  return { emitted, ops: new OperationsImpl(events) }
}

describe('the exemption flag', () => {
  it('exempts per mode, so answering during maintenance is not also a licence to write', async () => {
    const { ops } = makeOps()
    await ops.readOnly(true)
    expect(() => ops.assertOperationsForRoute('DELETE', { maintenance: true })).toThrow(
      expect.objectContaining({ code: 'AUTH_READONLY_MODE' }),
    )
    expect(() => ops.assertOperationsForRoute('DELETE', { readOnly: true })).not.toThrow()
  })

  it('names the mode it exempts, so a route cannot ask for the wrong one by accident', async () => {
    const { ops } = makeOps()
    await ops.maintenance(true)
    expect(() => ops.assertOperationsForRoute('POST', { readOnly: true })).toThrow(
      expect.objectContaining({ code: 'AUTH_MAINTENANCE' }),
    )
    expect(() => ops.assertOperationsForRoute('POST', { maintenance: true })).not.toThrow()
  })

  it('the toggles answer with the state they set', async () => {
    const { ops } = makeOps()

    // No follow-up `snapshot()` to see what a toggle actually did - and the
    // `since` stamp is the one it wrote, not one taken a moment later.
    const on = await ops.maintenance(true, { message: 'back at 5', retryAfterSec: 60 })
    expect(on.maintenance).toMatchObject({ message: 'back at 5', on: true, retryAfterSec: 60 })
    expect(on).toEqual(ops.snapshot())

    const frozen = await ops.readOnly(true)
    expect(frozen.readOnly.on).toBe(true)
    // The other mode is carried through untouched: this is the whole state.
    expect(frozen.maintenance.on).toBe(true)

    expect((await ops.maintenance(false)).maintenance).toEqual({ on: false })
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

  it('refuses any method it is not sure is safe, WebDAV and whatever HTTP adds next included', async () => {
    // An allow-list of writes passed anything it had not heard of.
    const { ops } = makeOps()
    await ops.readOnly(true)
    for (const m of ['MKCOL', 'MOVE', 'COPY', 'PROPPATCH', 'LOCK', 'QUERY']) {
      expect(() => ops.assertOperationsForRoute(m), m).toThrow(expect.objectContaining({ code: 'AUTH_READONLY_MODE' }))
    }
    for (const m of ['GET', 'HEAD', 'OPTIONS', 'TRACE']) {
      expect(() => ops.assertOperationsForRoute(m), m).not.toThrow()
    }
  })

  it('lets a mutating GET say so, because magic-link redemption is one', async () => {
    // Magic-link redemption and an OAuth callback are GETs that consume a one-time credential and
    // open a session, so during a migration freeze they kept writing.
    const { ops } = makeOps()
    await ops.readOnly(true)
    expect(() => ops.assertOperationsForRoute('GET')).not.toThrow()
    expect(() => ops.assertOperationsForRoute('GET', { mutates: true })).toThrow(
      expect.objectContaining({ code: 'AUTH_READONLY_MODE' }),
    )
  })

  it('fails closed on a missing method rather than raising a TypeError', async () => {
    // A raw TypeError is mapped to no status by anything in this library, so a freeze turned into
    // a five hundred.
    const { ops } = makeOps()
    await ops.readOnly(true)
    expect(() => ops.assertOperationsForRoute(undefined as never)).toThrow(
      expect.objectContaining({ code: 'AUTH_READONLY_MODE' }),
    )
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

  it('clamps a hint a client could not act on into one it can', async () => {
    const { ops } = makeOps()
    const hint = async (retryAfterSec: number) => {
      await ops.maintenance(true, { retryAfterSec })
      try {
        ops.assertOperationsForRoute('GET')
      } catch (e) {
        return (e as { meta: { retryAfter: number } }).meta.retryAfter
      }
    }
    // `Retry-After` is a non-negative whole number of seconds. A negative one is meaningless and a
    // NaN serialises to null, so neither survives to the client.
    expect(await hint(-30)).toBe(0)
    expect(await hint(Number.NaN)).toBe(60)
    expect(await hint(Number.POSITIVE_INFINITY)).toBe(60)
    expect(await hint(12.7)).toBe(12)
    expect(await hint(10_000_000)).toBe(86_400)
    expect(await hint(120)).toBe(120)
  })

  it('caps the operator message and strips what would start a second header', async () => {
    const { ops } = makeOps()
    await ops.maintenance(true, { message: `${'x'.repeat(100_000)}\r\nX-Injected: 1` })
    const thrown = (() => {
      try {
        ops.assertOperationsForRoute('GET')
      } catch (e) {
        return e as { meta: { message: string } }
      }
    })()
    expect(thrown?.meta.message).not.toContain('\r')
    expect(thrown?.meta.message).not.toContain('\n')
    expect(thrown?.meta.message.length).toBe(512)
  })

  it('leaves an ordinary operator message alone', async () => {
    const { ops } = makeOps()
    await ops.maintenance(true, { message: 'Back at 14:00 UTC.' })
    expect(() => ops.assertOperationsForRoute('GET')).toThrow(
      expect.objectContaining({ meta: { message: 'Back at 14:00 UTC.', retryAfter: 60 } }),
    )
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

  it('propagates read-only too, so a freeze is not one node deep', async () => {
    const { emitted, ops } = makeOps()
    await ops.readOnly(true)
    await ops.readOnly(false)
    expect(emitted.map((e) => e.name)).toEqual(['readonly.on', 'readonly.off'])
  })

  it('does not re-emit an event a subscriber applied, so a shared bus cannot loop', async () => {
    // The natural way to consume `maintenance.on` is to call `maintenance(true)` on the local
    // instance. That call used to emit again: immediate recursion in process, a broadcast storm
    // between nodes.
    const events = new InMemoryEvents()
    const ops = new OperationsImpl(events)
    let depth = 0
    events.on('maintenance.on', async () => {
      if (++depth < 5) await ops.maintenance(true)
    })
    await ops.maintenance(true)
    expect(depth).toBe(1)
  })

  it('emits nothing when a toggle changes nothing', async () => {
    const { emitted, ops } = makeOps()
    await ops.maintenance(false)
    await ops.maintenance(false)
    await ops.readOnly(false)
    expect(emitted).toHaveLength(0)
  })

  it('still emits when a re-assert changes the message an operator is showing', async () => {
    const { emitted, ops } = makeOps()
    await ops.maintenance(true, { message: 'back at 5' })
    await ops.maintenance(true, { message: 'back at 6' })
    expect(emitted.map((e) => e.payload)).toEqual([{ message: 'back at 5' }, { message: 'back at 6' }])
  })

  it('keeps the since stamp of an ongoing window across a re-assert', async () => {
    // Two nodes reporting one maintenance window used to disagree about when it started, and a
    // repeated deploy hook rewrote it each time.
    const { ops } = makeOps()
    await ops.maintenance(true)
    const first = ops.snapshot().maintenance.since
    await new Promise((r) => setTimeout(r, 5))
    await ops.maintenance(true, { message: 'still going' })
    expect(ops.snapshot().maintenance.since).toBe(first)
  })

  it('keeps the window that ended readable, message and retry hint included', async () => {
    const { ops } = makeOps()
    await ops.maintenance(true, { message: 'migrating', retryAfterSec: 120 })
    await ops.maintenance(false)
    expect(ops.snapshot().maintenance).toEqual({ on: false })
    expect(ops.snapshot().lastMaintenance).toMatchObject({ message: 'migrating', retryAfterSec: 120 })
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

  it('picks the switches back up from a store, so a restart mid-window stays inside it', async () => {
    // Nothing was persisted, and a rolling deploy is exactly when the window is open.
    let saved: Operations.State | null = null
    const store: Operations.Store = {
      // Nothing persisted rejects rather than answering null - the contract a host implements.
      load: async () => {
        if (saved === null) throw new AuthError('AUTH_OPERATION_NOT_FOUND')
        return saved
      },
      save: async (state) => {
        saved = state
      },
    }
    const ops = new OperationsImpl(new InMemoryEvents(), store)
    await ops.maintenance(true, { message: 'migrating' })

    const fresh = new OperationsImpl(new InMemoryEvents(), store)
    expect(fresh.snapshot().maintenance.on).toBe(false)
    await fresh.hydrate()
    expect(fresh.snapshot().maintenance).toMatchObject({ message: 'migrating', on: true })
  })

  it('keeps everything in this process when no store is wired', async () => {
    const { ops } = makeOps()
    await ops.maintenance(true)
    expect((await makeOps().ops.hydrate()).maintenance.on).toBe(false)
  })

  it('hydrating a store with nothing persisted yet keeps the defaults rather than failing', async () => {
    // The first boot of the first node: `load` refuses because there is no state, not because the store
    // broke. A store that is actually down still throws through, and takes the boot with it.
    const empty: Operations.Store = {
      load: async () => {
        throw new AuthError('AUTH_OPERATION_NOT_FOUND')
      },
      save: async () => {},
    }
    const ops = new OperationsImpl(new InMemoryEvents(), empty)

    expect((await ops.hydrate()).maintenance.on).toBe(false)
  })

  it('does not read a store that is down as a store with nothing in it', async () => {
    const down: Operations.Store = {
      load: async () => {
        throw new AuthError('AUTH_ADAPTER_UNAVAILABLE')
      },
      save: async () => {},
    }

    await expect(new OperationsImpl(new InMemoryEvents(), down).hydrate()).rejects.toMatchObject({
      code: 'AUTH_ADAPTER_UNAVAILABLE',
    })
  })
})
