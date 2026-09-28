import { describe, expect, it, vi } from 'vitest'
import { type Events, InMemoryEvents } from '~/core/events'
import { makeIdentity, makeSession } from '~/test/store-inputs'
import { DEFAULT_ANOMALY_CONFIG } from '../anomaly.constants'
import { AnomalyFacet, anomalyFacet } from '../anomaly.facet'
import type { Anomaly } from '../anomaly.types'

const identity = makeIdentity({ id: 'u' })
const session = makeSession({ id: 'sid', identityId: 'u' })
const NOW = 1_760_000_000_000

const signalOf = (kind: Anomaly.Kind, score: number): Anomaly.Signal => ({ evidence: {}, kind, score })

/** A detector whose entire output is chosen by the caller. */
const detectorOf = (id: string, signals: Anomaly.Signal[]): Anomaly.Detector => ({ evaluate: async () => signals, id })

/** A detector answering what the contract forbids, which a plugin can still do at runtime. */
function rogue(id: string, out: unknown): Anomaly.Detector {
  // @ts-expect-error: off-contract on purpose.
  return { evaluate: async () => out, id }
}

function makeFacet(cfg: Partial<Anomaly.Cfg> = {}) {
  const events = new InMemoryEvents()
  const emitted: Events.EventMap['suspicious'][] = []
  events.on('suspicious', (payload) => {
    emitted.push(payload)
  })
  return { emitted, facet: anomalyFacet(events, cfg) }
}

const run = (facet: AnomalyFacet, req: Partial<Anomaly.RequestSnapshot> = {}) =>
  facet.evaluate({ identity, req: { now: NOW, ...req }, session })

/** {@link run}, with the request let through. */
async function admitted(facet: AnomalyFacet): Promise<Anomaly.Result> {
  const result = await run(facet)
  await result.admit()
  return result
}

const refused = (detail: string) =>
  expect.objectContaining({ code: 'AUTH_MISCONFIGURED', meta: { detail: expect.stringContaining(detail) } })

/** What `fn` answers, and the console.error lines it logged. */
async function logged<T>(fn: () => Promise<T>): Promise<{ log: string; value: T }> {
  const error = vi.spyOn(console, 'error').mockImplementation(() => undefined)
  try {
    const value = await fn()
    return { log: error.mock.calls.map((args) => args.map(String).join(' ')).join('\n'), value }
  } finally {
    error.mockRestore()
  }
}

describe('construction refuses a ladder that would fail open', () => {
  describe.each(['threshold', 'stepUpAt', 'denyAt'] as const)('%s', (key) => {
    it.each([Number.NaN, Number.POSITIVE_INFINITY, -0.1, 1.1])('refuses %o', (value) => {
      expect(() => new AnomalyFacet(new InMemoryEvents(), { [key]: value })).toThrow(refused(key))
    })
  })

  it.each([Number.NaN, Number.POSITIVE_INFINITY, 0, -1, 2 ** 31])('refuses a detectorTimeoutMs of %o', (value) => {
    expect(() => new AnomalyFacet(new InMemoryEvents(), { detectorTimeoutMs: value })).toThrow(
      refused('detectorTimeoutMs'),
    )
  })

  it('accepts the defaults, and every bound itself', () => {
    expect(() => new AnomalyFacet(new InMemoryEvents())).not.toThrow()
    for (const cfg of [
      { denyAt: 1, detectorTimeoutMs: 1, stepUpAt: 0, threshold: 0 },
      { denyAt: 0, detectorTimeoutMs: 2 ** 31 - 1, stepUpAt: 0, threshold: 1 },
    ]) {
      expect(() => new AnomalyFacet(new InMemoryEvents(), cfg)).not.toThrow()
    }
  })

  it('reads an explicit undefined as omitted, so the default ladder applies', () => {
    const { facet } = makeFacet({
      denyAt: undefined,
      detectorTimeoutMs: undefined,
      stepUpAt: undefined,
      threshold: undefined,
    })
    expect(facet.decide([signalOf('new-device', 0.6999)])).toBe('allow')
    expect(facet.decide([signalOf('new-device', DEFAULT_ANOMALY_CONFIG.stepUpAt)])).toBe('step-up')
    expect(facet.decide([signalOf('new-device', DEFAULT_ANOMALY_CONFIG.denyAt)])).toBe('deny')
  })

  // Read from JSON, as an operator's reactions usually are: nothing typed them on the way in.
  it.each([
    ['a misspelled decision', '{"*":{"new-device":"denied"}}', "reactions['*']['new-device']"],
    ['a flat table with no detector level', '{"new-device":"deny"}', "reactions['new-device'] must be an object"],
  ])('refuses %s, which would apply to nothing and say nothing', (_, json, detail) => {
    expect(() => new AnomalyFacet(new InMemoryEvents(), { reactions: JSON.parse(json) })).toThrow(refused(detail))
  })

  it('fills what a partial config leaves out from the defaults', () => {
    const facet = new AnomalyFacet(new InMemoryEvents(), { stepUpAt: 0.5 })
    expect(facet.decide([signalOf('new-device', 0.49)])).toBe('allow')
    expect(facet.decide([signalOf('new-device', 0.5)])).toBe('step-up')
    expect(facet.decide([signalOf('new-device', DEFAULT_ANOMALY_CONFIG.denyAt)])).toBe('deny')
  })

  it('logs a denyAt below stepUpAt, which leaves step-up dead, and still denies on it', async () => {
    const level = await logged(async () => new AnomalyFacet(new InMemoryEvents(), { denyAt: 0.7, stepUpAt: 0.7 }))
    expect(level.log).toBe('')
    const inverted = await logged(async () => new AnomalyFacet(new InMemoryEvents(), { denyAt: 0.5, stepUpAt: 0.8 }))
    expect(inverted.log).toContain('nothing can ever step up')
    expect(inverted.value.decide([signalOf('new-device', 0.6)])).toBe('deny')
  })
})

describe('the registry', () => {
  it('lists ids in registration order, and unregisters by id', () => {
    const { facet } = makeFacet()
    for (const id of ['a', 'b', 'c']) facet.register(detectorOf(id, []))
    expect(facet.list()).toEqual(['a', 'b', 'c'])
    expect(facet.unregister('b')).toBe(true)
    expect(facet.unregister('missing')).toBe(false)
    expect(facet.list()).toEqual(['a', 'c'])
  })

  it('refuses an id already registered, which would count twice, until it is unregistered', async () => {
    const { facet } = makeFacet()
    const d = detectorOf('new-device', [signalOf('new-device', 0.5)])
    facet.register(d)
    expect(() => facet.register(d)).toThrow(refused('already registered'))
    expect((await run(facet)).score).toBe(0.5)

    facet.unregister('new-device')
    expect(() => facet.register(d)).not.toThrow()
    expect(facet.list()).toEqual(['new-device'])
  })

  it.each([
    ['the id reactions reserve for any detector', { id: '*' }, 'reserved for the reactions wildcard'],
    ['an empty id', { id: '' }, 'non-empty string id'],
    ['an id that is not a string', { id: 42 }, 'non-empty string id'],
    ['no evaluate', { evaluate: undefined }, 'evaluate function'],
    ['a record that is not a function', { record: 'yes' }, 'record only as a function'],
  ])('refuses %s', (_, over, detail) => {
    const { facet } = makeFacet()
    expect(() => facet.register(Object.assign(detectorOf('d', []), over))).toThrow(refused(detail))
    expect(facet.list()).toEqual([])
    expect(() => facet.register(Object.assign(detectorOf('d', []), { record: async () => undefined }))).not.toThrow()
  })
})

describe('the aggregate saturates, so neither count nor sign can steer it', () => {
  it('combines noisy-or: two 0.5 signals are 0.75, not 1', async () => {
    const { facet } = makeFacet()
    facet.register(detectorOf('a', [signalOf('new-device', 0.5)]))
    facet.register(detectorOf('b', [signalOf('high-velocity', 0.5)]))
    expect(await run(facet)).toMatchObject({ decision: 'step-up', score: 0.75 })
  })

  it('many weak signals saturate instead of summing into a deny', async () => {
    const { facet } = makeFacet()
    for (let i = 0; i < 5; i++) facet.register(detectorOf(`d${i}`, [signalOf('off-hours', 0.2)]))
    // 1 - 0.8^5; a plain sum would be 1.0 and a deny.
    expect(await run(facet)).toMatchObject({ decision: 'allow', score: 0.67232 })
  })

  it('enough strong signals still reach deny', async () => {
    const { facet } = makeFacet()
    for (let i = 0; i < 4; i++) facet.register(detectorOf(`d${i}`, [signalOf('off-hours', 0.6)]))
    expect((await run(facet)).decision).toBe('deny')
  })

  it('a negative score is clamped away rather than vetoing another detector', async () => {
    const { facet } = makeFacet()
    facet.register(detectorOf('honest', [signalOf('impossible-travel', 1)]))
    facet.register(detectorOf('hostile', [signalOf('new-device', -5)]))
    expect(await run(facet)).toMatchObject({ decision: 'deny', score: 1 })
  })

  it('a score above one is worth exactly one', async () => {
    const { facet } = makeFacet()
    facet.register(detectorOf('a', [signalOf('new-device', 50)]))
    expect(await run(facet)).toMatchObject({ score: 1, signals: [{ score: 1 }] })
  })

  it('decides at each threshold inclusively', () => {
    const { facet } = makeFacet({ denyAt: 0.95, stepUpAt: 0.7 })
    expect(facet.decide([signalOf('new-device', 0.6999)])).toBe('allow')
    expect(facet.decide([signalOf('new-device', 0.7)])).toBe('step-up')
    expect(facet.decide([signalOf('new-device', 0.9499)])).toBe('step-up')
    expect(facet.decide([signalOf('new-device', 0.95)])).toBe('deny')
  })

  it('no detectors at all is an allow with no event', async () => {
    const { facet, emitted } = makeFacet()
    expect(await run(facet)).toMatchObject({ decision: 'allow', score: 0, signals: [] })
    expect(emitted).toEqual([])
  })
})

describe('the suspicious event', () => {
  it('fires at the threshold, naming every contributing kind, and not below it', async () => {
    const { facet, emitted } = makeFacet({ threshold: 0.5 })
    facet.register(detectorOf('a', [signalOf('new-device', 0.4)]))
    await run(facet)
    expect(emitted).toEqual([])

    facet.register(detectorOf('b', [signalOf('off-hours', 0.4)]))
    await run(facet)
    expect(emitted).toEqual([expect.objectContaining({ identityId: 'u', score: 0.64, signal: 'new-device+off-hours' })])
  })

  it.each([
    ['a NaN-driven deny, whose reported score is zero', {}, signalOf('impossible-travel', Number.NaN), 'deny'],
    ['a step-up under a raised threshold', { stepUpAt: 0.5, threshold: 0.9 }, signalOf('new-device', 0.6), 'step-up'],
    [
      'a deny forced by a reaction',
      { reactions: { '*': { 'new-device': 'deny' } } },
      signalOf('new-device', 0.01),
      'deny',
    ],
  ] as const)('records %s, whatever the threshold', async (_, cfg, signal, decision) => {
    const { facet, emitted } = makeFacet(cfg)
    facet.register(detectorOf('a', [signal]))
    const result = await run(facet)
    expect(result.decision).toBe(decision)
    expect(emitted).toEqual([
      expect.objectContaining({ meta: expect.objectContaining({ decision }), score: result.score }),
    ])
  })

  it('names the identity the request carried, empty id included', async () => {
    const { facet, emitted } = makeFacet({ threshold: 0.1 })
    facet.register(detectorOf('a', [signalOf('new-device', 0.5)]))
    await facet.evaluate({ identity: makeIdentity({ id: '' }), req: { now: NOW }, session })
    expect(emitted[0]).toHaveProperty('identityId', '')
  })

  it('stays quiet at threshold zero when no signal fired', async () => {
    const { facet, emitted } = makeFacet({ threshold: 0 })
    facet.register(detectorOf('a', []))
    await run(facet)
    expect(emitted).toEqual([])
  })

  it('carries evidence verbatim, however large, since nothing clips it', async () => {
    const { facet, emitted } = makeFacet({ threshold: 0.1 })
    const blob = 'x'.repeat(200_000)
    facet.register(detectorOf('a', [{ evidence: { blob }, kind: 'new-device', score: 0.5 }]))
    await run(facet)
    expect(emitted).toMatchObject([{ meta: { signals: [{ evidence: { blob } }] } }])
  })

  it('a bus that throws is logged, and the deny stands', async () => {
    const bus: Events.IBus = {
      emit: async () => {
        throw new Error('bus down')
      },
      on: () => () => undefined,
    }
    const facet = new AnomalyFacet(bus)
    facet.register(detectorOf('a', [signalOf('new-device', 1)]))
    const { log, value } = await logged(() => run(facet))
    expect(log).toContain('could not emit "suspicious"')
    expect(value.decision).toBe('deny')
  })
})

describe('reactions raise the ladder, or mute a signal outright', () => {
  it('an allow mutes that signal, and only that one', async () => {
    const { facet } = makeFacet({ reactions: { '*': { 'new-device': 'allow' } } })
    facet.register(detectorOf('a', [signalOf('new-device', 0.8)]))
    // Out of the reported list too, or it names a kind the score beside it was not told about.
    expect(await run(facet)).toMatchObject({ decision: 'allow', score: 0, signals: [] })

    facet.register(detectorOf('b', [signalOf('off-hours', 0.8)]))
    const partial = await run(facet)
    expect(partial.decision).toBe('step-up')
    expect(partial.signals.map((s) => s.kind)).toEqual(['off-hours'])
  })

  it('a step-up reaction fires on a signal far below stepUpAt', async () => {
    const { facet } = makeFacet({ reactions: { '*': { 'impossible-travel': 'step-up' } } })
    facet.register(detectorOf('a', [signalOf('impossible-travel', 0.01)]))
    expect((await run(facet)).decision).toBe('step-up')
  })

  it('a score at denyAt outranks a step-up reaction', async () => {
    const { facet } = makeFacet({ reactions: { '*': { 'new-device': 'step-up' } } })
    facet.register(detectorOf('a', [signalOf('new-device', 0.99)]))
    expect((await run(facet)).decision).toBe('deny')
  })

  it('the strongest reaction across the kinds present wins, and one for an absent kind is ignored', async () => {
    const { facet } = makeFacet({
      reactions: { '*': { 'impossible-travel': 'deny', 'new-device': 'step-up', 'off-hours': 'allow' } },
    })
    facet.register(detectorOf('a', [signalOf('new-device', 0.01), signalOf('off-hours', 0.01)]))
    expect((await run(facet)).decision).toBe('step-up')
    facet.register(detectorOf('b', [signalOf('impossible-travel', 0.01)]))
    expect((await run(facet)).decision).toBe('deny')
  })

  it('a reaction scoped to a detector does not apply to another emitting the same kind', async () => {
    const bare = makeFacet({ reactions: { '*': { 'impossible-travel': 'deny' } } })
    bare.facet.register(detectorOf('impostor', [signalOf('impossible-travel', 0)]))
    expect((await run(bare.facet)).decision).toBe('deny')

    const scoped = makeFacet({ reactions: { 'travel.detector': { 'impossible-travel': 'deny' } } })
    scoped.facet.register(detectorOf('impostor', [signalOf('impossible-travel', 0)]))
    expect((await run(scoped.facet)).decision).toBe('allow')
    scoped.facet.register(detectorOf('travel.detector', [signalOf('impossible-travel', 0)]))
    expect((await run(scoped.facet)).decision).toBe('deny')
  })

  it('stamps every signal with the detector that produced it, over what the detector claimed', async () => {
    const { facet } = makeFacet()
    facet.register(detectorOf('travel.detector', [{ ...signalOf('impossible-travel', 0.1), source: 'forged' }]))
    expect((await run(facet)).signals).toMatchObject([{ source: 'travel.detector' }])
  })

  it('reads both levels as own keys, so a prototype member cannot shadow the wildcard', async () => {
    // Typed apart: a `toString` key takes its contextual type from `Object.prototype`, not the table.
    const deny: Anomaly.Decision = 'deny'
    const byKind = makeFacet({ reactions: { '*': { toString: deny }, d: { other: 'step-up' } } })
    byKind.facet.register(detectorOf('d', [signalOf('toString', 0.01)]))
    expect((await run(byKind.facet)).decision).toBe('deny')

    const byId = makeFacet({ reactions: { '*': { name: 'deny' } } })
    byId.facet.register(detectorOf('constructor', [signalOf('name', 0.01)]))
    expect((await run(byId.facet)).decision).toBe('deny')
  })
})

describe('a misbehaving detector is logged and skipped, and the rest still decide', () => {
  it.each([
    ['rejects', { evaluate: () => Promise.reject(new Error('boom')), id: 'bad' }, 'threw'],
    ['rejects with a non-Error', { evaluate: () => Promise.reject('a string'), id: 'bad' }, 'threw'],
    [
      'throws synchronously',
      {
        evaluate: () => {
          throw new Error('sync')
        },
        id: 'bad',
      },
      'threw',
    ],
    ['hangs past the timeout', { evaluate: () => new Promise<never>(() => undefined), id: 'bad' }, 'exceeded 10ms'],
    ['answers a non-array', rogue('bad', 'not-an-array'), 'returned non-array'],
  ])('one that %s', async (_, bad, reason) => {
    const { facet } = makeFacet({ detectorTimeoutMs: 10 })
    facet.register(bad)
    facet.register(detectorOf('good', [signalOf('new-device', 0.5)]))
    const { log, value } = await logged(() => run(facet))
    expect(log).toContain('"bad"')
    expect(log).toContain(reason)
    expect(value).toMatchObject({ score: 0.5, signals: [{ source: 'good' }] })
  })

  it('drops each malformed signal and keeps the well-formed one beside it', async () => {
    const { facet } = makeFacet()
    facet.register(
      rogue('mixed', [
        null,
        {},
        { evidence: {}, kind: 42, score: 0.5 },
        { evidence: {}, kind: '', score: 0.5 },
        { evidence: {}, kind: 'new-device', score: '0.5' },
        { evidence: 'ip=203.0.113.9', kind: 'new-device', score: 0.5 },
        { evidence: ['203.0.113.9'], kind: 'new-device', score: 0.5 },
        { evidence: {}, kind: 'new-device', score: 0.6 },
      ]),
    )
    const { log, value } = await logged(() => run(facet))
    expect(log).toContain('invalid signal')
    expect(value.signals).toEqual([{ evidence: {}, kind: 'new-device', score: 0.6, source: 'mixed' }])
  })

  it('reads a signal with no evidence as empty evidence', async () => {
    const { facet } = makeFacet()
    facet.register(rogue('a', [{ kind: 'new-device', score: 0.5 }]))
    expect(await run(facet)).toMatchObject({ score: 0.5, signals: [{ evidence: {} }] })
  })

  it.each([Number.NaN, Number.POSITIVE_INFINITY])(
    'a %o score is well-formed, so it is kept, and it denies',
    async (score) => {
      const { facet } = makeFacet()
      facet.register(detectorOf('bad', [signalOf('new-device', score)]))
      facet.register(detectorOf('good', [signalOf('off-hours', 0.3)]))
      // The score reports what is finite; the verdict is not taken from it.
      expect(await run(facet)).toMatchObject({ decision: 'deny', score: 0.3 })
    },
  )

  it('runs detectors concurrently, so their latencies overlap rather than add', async () => {
    const { facet } = makeFacet()
    const order: string[] = []
    for (const id of ['a', 'b', 'c']) {
      facet.register({
        evaluate: async () => {
          order.push(`start-${id}`)
          await new Promise((r) => setTimeout(r, 5))
          order.push(`end-${id}`)
          return []
        },
        id,
      })
    }
    await run(facet)
    expect(order.slice(0, 3)).toEqual(['start-a', 'start-b', 'start-c'])
  })

  it('hands every detector a frozen snapshot, geo included, so none can edit what the others read', async () => {
    const { facet } = makeFacet()
    const writes: boolean[] = []
    let observed: Anomaly.Context['req'] | undefined
    facet.register({
      evaluate: async ({ req }) => {
        writes.push(Reflect.set(req, 'ip', '198.51.100.1'), Reflect.set(req.geo ?? {}, 'country', 'XX'))
        return []
      },
      id: 'mutator',
    })
    facet.register({
      evaluate: async ({ req }) => {
        observed = req
        return []
      },
      id: 'observer',
    })
    await run(facet, { geo: { country: 'FR' }, ip: '203.0.113.9' })
    expect(writes).toEqual([false, false])
    expect(observed).toMatchObject({ geo: { country: 'FR' }, ip: '203.0.113.9' })
  })

  it('logs a request time that is not a number, since no time-based detector can score it', async () => {
    const { facet } = makeFacet()
    expect((await logged(() => run(facet))).log).toBe('')
    expect((await logged(() => run(facet, { now: Number.NaN }))).log).toContain('req.now is not a finite number')
  })
})

describe('record runs once the request is admitted, and cannot change the verdict', () => {
  it('evaluating alone records nothing', async () => {
    const { facet } = makeFacet()
    const record = vi.fn(async () => undefined)
    facet.register({ evaluate: async () => [signalOf('new-device', 0.8)], id: 'd', record })
    const result = await run(facet)
    expect(record).not.toHaveBeenCalled()
    await result.admit()
    expect(record).toHaveBeenCalledWith(expect.anything(), 'step-up')
  })

  it('hands every detector the decision the request got', async () => {
    const { facet } = makeFacet()
    const recorded: string[] = []
    for (const [id, score] of [
      ['low', 0.1],
      ['high', 0.96],
    ] as const) {
      facet.register({
        evaluate: async () => [signalOf('new-device', score)],
        id,
        record: async (_ctx, decision) => {
          recorded.push(`${id}:${decision}`)
        },
      })
    }
    expect((await admitted(facet)).decision).toBe('deny')
    expect(recorded.sort()).toEqual(['high:deny', 'low:deny'])
  })

  it.each([
    ['rejects', () => Promise.reject(new Error('store down'))],
    [
      'throws synchronously',
      () => {
        throw new Error('bug')
      },
    ],
    ['hangs', () => new Promise<void>(() => undefined)],
  ])('a record that %s is logged, and the deny stands', async (_, record) => {
    const { facet } = makeFacet({ detectorTimeoutMs: 10 })
    facet.register({ evaluate: async () => [signalOf('new-device', 1)], id: 'd', record })
    const { log, value } = await logged(() => admitted(facet))
    expect(log).toContain('"d" could not record')
    expect(value.decision).toBe('deny')
  })

  it.each([
    ['throws', { evaluate: () => Promise.reject(new Error('store down')), id: 'd' }],
    ['overruns the timeout', { evaluate: () => new Promise<never>(() => undefined), id: 'd' }],
    ['answers a non-array', rogue('d', 'not-an-array')],
  ])('records nothing for a detector that %s, which judged nothing', async (_, detector) => {
    const { facet } = makeFacet({ detectorTimeoutMs: 10 })
    const record = vi.fn(async () => undefined)
    const answered = vi.fn(async () => undefined)
    facet.register(Object.assign(detector, { record }))
    facet.register({ evaluate: async () => [], id: 'answered', record: answered })
    await logged(() => admitted(facet))
    expect(record).not.toHaveBeenCalled()
    expect(answered).toHaveBeenCalledWith(expect.anything(), 'allow')
  })

  it('records nothing for a detector registered while the request was scored', async () => {
    const { facet } = makeFacet()
    const late = vi.fn(async () => undefined)
    facet.register({
      evaluate: async () => {
        if (!facet.list().includes('late')) facet.register({ evaluate: async () => [], id: 'late', record: late })
        return []
      },
      id: 'registrar',
    })
    await admitted(facet)
    expect(late).not.toHaveBeenCalled()
    await admitted(facet)
    expect(late).toHaveBeenCalledTimes(1)
  })
})

describe('decide walks the same ladder over signals a caller kept', () => {
  it('denies on a score that is not a number, beside any other', () => {
    const { facet } = makeFacet()
    expect(facet.decide([signalOf('new-device', Number.NaN)])).toBe('deny')
    expect(facet.decide([signalOf('off-hours', 0.1), signalOf('new-device', Number.POSITIVE_INFINITY)])).toBe('deny')
  })

  it('clamps what it is handed, so an out-of-range score cannot lower the verdict', () => {
    const { facet } = makeFacet()
    // Unclamped, two scores of 1.5 multiply the remainder by a positive 0.25 and the aggregate falls.
    expect(facet.decide([signalOf('new-device', 1.5), signalOf('impossible-travel', 1.5)])).toBe('deny')
    // Unclamped, `1 - (-9)` multiplies the remainder by ten and mutes the real signal beside it.
    expect(facet.decide([signalOf('new-device', 0.8), signalOf('impossible-travel', -9)])).toBe('step-up')
  })

  it('agrees with evaluate on the signals evaluate reported', async () => {
    const { facet } = makeFacet({ reactions: { '*': { 'off-hours': 'allow' } } })
    facet.register(detectorOf('d', [signalOf('new-device', 1.5), signalOf('off-hours', 0.9)]))
    const result = await run(facet)
    expect(result.decision).toBe('deny')
    expect(facet.decide(result.signals)).toBe(result.decision)
  })
})
