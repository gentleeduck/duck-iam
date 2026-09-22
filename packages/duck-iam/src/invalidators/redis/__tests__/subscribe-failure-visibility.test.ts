import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../../core/engine/engine'
import { createIamRedisInvalidator } from '../index'

// A node whose subscribe failed: `publish` retries it, `healthCheck()` reports it without failing, and the warning
// says where retries come from. Each has a control.

/** A fake client whose `subscribe` fails for the first `failUntilAttempt` attempts. */
function makeClient(opts: { failUntilAttempt: number }) {
  const state = { attempts: 0, published: [] as string[] }
  return {
    state,
    client: {
      publish: (_channel: string, payload: string) => {
        state.published.push(payload)
        return Promise.resolve(1)
      },
      subscribe: (_channel: string, _handler: (message: string) => void) => {
        state.attempts++
        return state.attempts <= opts.failUntilAttempt
          ? Promise.reject(new Error('NOAUTH Authentication required'))
          : Promise.resolve()
      },
      unsubscribe: () => Promise.resolve(),
    },
  }
}

/** Lets the invalidator's `.then`/`.catch` chain settle. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 5))

describe('a redis invalidator that cannot subscribe', () => {
  let warn: ReturnType<typeof vi.spyOn>
  beforeEach(() => {
    warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
  })
  afterEach(() => {
    warn.mockRestore()
    vi.useRealTimers()
  })

  it('reports itself unsubscribed through healthCheck, without failing the probe', async () => {
    const { client } = makeClient({ failUntilAttempt: Number.POSITIVE_INFINITY })
    const engine = new IamEngine({
      adapter: new IamMemoryAdapter(),
      invalidator: createIamRedisInvalidator({ client }),
    })
    await settle()

    const health = await engine.healthCheck()
    expect(health.invalidator).toEqual({ subscribed: false })
    // Correlated across the fleet: failing the probe would pull every replica.
    expect(health.ok).toBe(true)
    expect(health.adapter).toBe('ok')
  })

  it('CONTROL: a subscribed invalidator adds no `invalidator` field at all', async () => {
    const { client } = makeClient({ failUntilAttempt: 0 })
    const engine = new IamEngine({
      adapter: new IamMemoryAdapter(),
      invalidator: createIamRedisInvalidator({ client }),
    })
    await settle()

    const health = await engine.healthCheck()
    expect(health.invalidator).toBeUndefined()
    expect('invalidator' in health).toBe(false)
    expect(health.ok).toBe(true)
  })

  it('CONTROL: an engine with no invalidator adds no `invalidator` field', async () => {
    const engine = new IamEngine({ adapter: new IamMemoryAdapter() })
    const health = await engine.healthCheck()
    expect(health.invalidator).toBeUndefined()
    expect(health.ok).toBe(true)
  })

  it('retries the subscribe on a later publish, and recovers when the broker returns', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const { client, state } = makeClient({ failUntilAttempt: 1 })
    const inv = createIamRedisInvalidator({ client })
    const engine = new IamEngine({ adapter: new IamMemoryAdapter(), invalidator: inv })
    await vi.advanceTimersByTimeAsync(10)
    expect(state.attempts).toBe(1)
    expect(inv.status?.()).toEqual({ subscribed: false })

    // Inside the floor: a write must not turn an outage into an attempt per write.
    await engine.admin.saveRole({ id: 'r1', name: 'R1', permissions: [] })
    await vi.advanceTimersByTimeAsync(10)
    expect(state.attempts).toBe(1)

    // Past the floor: the next write retries, and this time the broker answers.
    await vi.advanceTimersByTimeAsync(5_001)
    await engine.admin.saveRole({ id: 'r2', name: 'R2', permissions: [] })
    await vi.advanceTimersByTimeAsync(10)
    expect(state.attempts).toBe(2)
    expect(inv.status?.()).toEqual({ subscribed: true })
    expect(await engine.healthCheck().then((h) => h.invalidator)).toBeUndefined()
  })

  it('CONTROL: a healthy invalidator is not re-subscribed by publishing', async () => {
    const { client, state } = makeClient({ failUntilAttempt: 0 })
    const inv = createIamRedisInvalidator({ client })
    const engine = new IamEngine({ adapter: new IamMemoryAdapter(), invalidator: inv })
    await settle()
    expect(state.attempts).toBe(1)

    for (let i = 0; i < 5; i++) await engine.admin.saveRole({ id: `r${i}`, name: 'R', permissions: [] })
    await settle()

    expect(state.attempts).toBe(1)
    expect(state.published.length).toBe(5)
  })

  it('never opens a subscription from publish alone, on an invalidator that never subscribed', async () => {
    // A subscribed Redis client stops accepting `publish`, so the retry must never initiate for a publish-only caller.
    const { client, state } = makeClient({ failUntilAttempt: 0 })
    const inv = createIamRedisInvalidator({ client })

    inv.publish({ kind: 'all' })
    inv.publish({ kind: 'policies' })
    await settle()

    expect(state.attempts).toBe(0)
    expect(state.published.length).toBe(2)
    expect(inv.status?.()).toEqual({ subscribed: false })
  })

  it('tells the operator that retries ride on publish and that a read-only node never retries', async () => {
    const { client } = makeClient({ failUntilAttempt: Number.POSITIVE_INFINITY })
    createIamRedisInvalidator({ client }).subscribe(() => {})
    await settle()

    const message = warn.mock.calls.map((c: unknown[]) => String(c[0])).join('\n')
    // Pin the wording itself: the warning must not promise a recovery no code performs.
    expect(message).toContain('serves stale allow decisions')
    expect(message).toContain('A retry is attempted from publish()')
    expect(message).toContain('a node that never writes never retries')
    expect(message).toContain('invalidator: { subscribed: false }')
  })

  it('omits the field and warns once when `status` is present but broken', async () => {
    const broken = {
      publish: () => undefined,
      status: () => 'not an object',
      subscribe: () => () => {},
    }
    const engine = new IamEngine({ adapter: new IamMemoryAdapter() })
    // A deliberately malformed third-party invalidator: `status` returns the
    // wrong shape, which the published type forbids and a JS caller can still do.
    engine.setInvalidator(broken as unknown as Parameters<typeof engine.setInvalidator>[0])

    const first = await engine.healthCheck()
    const second = await engine.healthCheck()

    expect(first.invalidator).toBeUndefined()
    expect(first.ok).toBe(true)
    expect(second.invalidator).toBeUndefined()
    const engineWarns = warn.mock.calls.filter((c: unknown[]) =>
      String(c[0]).includes('healthCheck: the attached invalidator'),
    )
    expect(engineWarns.length).toBe(1)
  })

  it('survives a `status` that throws rather than turning /healthz into a 500', async () => {
    const throwing = {
      publish: () => undefined,
      status: () => {
        throw new Error('client destroyed')
      },
      subscribe: () => () => {},
    }
    const engine = new IamEngine({ adapter: new IamMemoryAdapter() })
    engine.setInvalidator(throwing)

    const health = await engine.healthCheck()
    expect(health.ok).toBe(true)
    expect(health.invalidator).toBeUndefined()
  })

  it('CONTROL: an invalidator with no `status` at all is reported on, not warned about', async () => {
    const legacy = { publish: () => undefined, subscribe: () => () => {} }
    const engine = new IamEngine({ adapter: new IamMemoryAdapter() })
    engine.setInvalidator(legacy)

    const health = await engine.healthCheck()
    expect(health.invalidator).toBeUndefined()
    expect(health.ok).toBe(true)
    expect(warn.mock.calls.filter((c: unknown[]) => String(c[0]).includes('healthCheck:')).length).toBe(0)
  })
})
