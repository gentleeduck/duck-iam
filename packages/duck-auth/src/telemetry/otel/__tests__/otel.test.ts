import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthInMemoryEvents } from '../../../core/events'
import { AuthOtelInstrumentation } from '../index'

interface CapturedCounter {
  name: string
  counter: AuthOtelInstrumentation.ICounter
  adds: Array<{ value: number; attrs?: Record<string, string | number | boolean> }>
}

function makeMeter(): { meter: AuthOtelInstrumentation.IMeter; counters: Map<string, CapturedCounter> } {
  const counters = new Map<string, CapturedCounter>()
  function makeCounter(name: string): AuthOtelInstrumentation.ICounter {
    const captured: CapturedCounter = {
      name,
      counter: {
        add: vi.fn((value, attrs) => {
          captured.adds.push({ value, attrs })
        }),
      },
      adds: [],
    }
    counters.set(name, captured)
    return captured.counter
  }
  const meter: AuthOtelInstrumentation.IMeter = {
    createCounter: (name) => makeCounter(name),
    createUpDownCounter: (name) => makeCounter(name),
    createHistogram: (name): AuthOtelInstrumentation.IHistogram => ({
      record: vi.fn(),
    }),
  }
  return { meter, counters }
}

describe('AuthOtelInstrumentation', () => {
  let bus: AuthInMemoryEvents
  let meter: AuthOtelInstrumentation.IMeter
  let counters: Map<string, CapturedCounter>
  let cleanup: () => void

  beforeEach(() => {
    bus = new AuthInMemoryEvents()
    ;({ meter, counters } = makeMeter())
    const inst = new AuthOtelInstrumentation({ meter, prefix: 'test' })
    cleanup = inst.attach(bus)
  })

  it('declares the expected metric names with the configured prefix', () => {
    const names = [...counters.keys()].sort()
    expect(names).toEqual([
      'test.identity.impersonated.total',
      'test.lockout.total',
      'test.mfa.enrolled.total',
      'test.mfa.removed.total',
      'test.session.active',
      'test.session.rotated.total',
      'test.signin.total',
      'test.signup.total',
      'test.suspicious.total',
    ])
  })

  it('signin.success increments signin.total with provider + result attributes', async () => {
    await bus.emit('signin.success', {
      identity: { id: 'u1' } as never,
      factors: [{ method: 'password', completedAt: 0 }],
    })
    const adds = counters.get('test.signin.total')!.adds
    expect(adds).toHaveLength(1)
    expect(adds[0]!.attrs).toMatchObject({ provider: 'password', result: 'success' })
  })

  it('signin.failed records reason attribute', async () => {
    await bus.emit('signin.failed', { providerId: 'password', reason: 'invalid-credentials' })
    const adds = counters.get('test.signin.total')!.adds
    expect(adds[0]!.attrs).toMatchObject({
      provider: 'password',
      result: 'failed',
      reason: 'invalid-credentials',
    })
  })

  it('session.created + session.revoked move the up-down counter', async () => {
    await bus.emit('session.created', { session: {} as never, identity: null })
    await bus.emit('session.created', { session: {} as never, identity: null })
    await bus.emit('session.revoked', { sessionId: 's1', identityId: 'u1' })
    const adds = counters.get('test.session.active')!.adds
    expect(adds.map((a) => a.value)).toEqual([1, 1, -1])
  })

  it('lockout fires lockout.total once per event', async () => {
    await bus.emit('lockout', { identityId: 'u1', until: 0 })
    await bus.emit('lockout', { identityId: 'u1', until: 0 })
    expect(counters.get('test.lockout.total')!.adds).toHaveLength(2)
  })

  it('suspicious buckets severity by score', async () => {
    await bus.emit('suspicious', { signal: 'impossible-travel', score: 0.1, meta: {} })
    await bus.emit('suspicious', { signal: 'impossible-travel', score: 0.5, meta: {} })
    await bus.emit('suspicious', { signal: 'impossible-travel', score: 0.9, meta: {} })
    const adds = counters.get('test.suspicious.total')!.adds
    expect(adds.map((a) => a.attrs?.severity)).toEqual(['low', 'medium', 'high'])
  })

  it('cleanup detaches every listener', async () => {
    cleanup()
    await bus.emit('signup.completed', { identity: { id: 'u1' } as never })
    expect(counters.get('test.signup.total')!.adds).toHaveLength(0)
  })

  it('default attributes appended to every record', async () => {
    bus = new AuthInMemoryEvents()
    ;({ meter, counters } = makeMeter())
    const inst = new AuthOtelInstrumentation({
      meter,
      prefix: 'test',
      defaultAttributes: { 'service.name': 'auth', env: 'prod' },
    })
    inst.attach(bus)
    await bus.emit('signup.completed', { identity: { id: 'u1' } as never })
    expect(counters.get('test.signup.total')!.adds[0]!.attrs).toMatchObject({
      'service.name': 'auth',
      env: 'prod',
    })
  })

  it('refuses construction without a meter', () => {
    expect(
      () => new AuthOtelInstrumentation({ meter: null as unknown as AuthOtelInstrumentation.IMeter }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH/MISCONFIGURED' }))
  })
})
