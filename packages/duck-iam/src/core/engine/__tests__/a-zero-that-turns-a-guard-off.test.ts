import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { _resetDisabledGuardWarnings, IamEngine } from '../engine'

// `0` is a documented, legal "off" for three options, and each one it turns off is a fail-closed mechanism.
// It is also what `Number('')` gives, so an environment variable that is set but empty lands on it rather than
// on the non-finite guard beside it.

const POST = { attributes: {}, id: 'p1', type: 'post' }
const ROLES: AccessControl.IRole[] = [{ id: 'reader', name: 'R', permissions: [{ action: 'read', resource: 'post' }] }]

const seed = () => new IamMemoryAdapter({ assignments: { u1: ['reader'] }, policies: [], roles: ROLES })

/** An adapter whose reads never settle, standing in for a store that has stopped answering. */
function hungAdapter() {
  return new Proxy(seed(), {
    get(target, prop, recv) {
      if (prop === 'listPolicies') return () => new Promise(() => {})
      return Reflect.get(target, prop, recv)
    },
  })
}

/** `'settled'`, `'threw: …'`, or `'HUNG'` when nothing came back inside the window. */
async function outcomeOf(p: Promise<unknown>): Promise<string> {
  return Promise.race([
    p.then(() => 'settled').catch((e) => `threw: ${e instanceof Error ? e.message.slice(0, 30) : String(e)}`),
    new Promise<string>((resolve) => setTimeout(() => resolve('HUNG'), 150)),
  ])
}

function built<T>(make: () => T): { value: T; warnings: string[] } {
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
  try {
    const value = make()
    return { value, warnings: warn.mock.calls.map((args) => args.map(String).join(' ')) }
  } finally {
    warn.mockRestore()
  }
}

beforeEach(() => {
  _resetDisabledGuardWarnings()
})

describe('a zero that turns a guard off', () => {
  it('names adapterTimeoutMs and what stops happening', () => {
    const { warnings } = built(() => new IamEngine({ adapter: seed(), adapterTimeoutMs: 0, mode: 'production' }))

    expect(warnings).toHaveLength(1)
    expect(warnings[0]).toContain('adapterTimeoutMs')
    expect(warnings[0]).toContain('hangs every check instead of denying it')
    expect(warnings[0]).toContain("`Number('')` is 0")
  })

  it('names hookTimeoutMs and maxConcurrentSubjectLoads too, one line each', () => {
    const { warnings } = built(
      () =>
        new IamEngine({
          adapter: seed(),
          hookTimeoutMs: 0,
          maxConcurrentSubjectLoads: 0,
          mode: 'production',
        }),
    )

    expect(warnings).toHaveLength(2)
    expect(warnings.join('\n')).toContain('hookTimeoutMs')
    expect(warnings.join('\n')).toContain('maxConcurrentSubjectLoads')
  })

  it('says nothing for the defaults, or for a real timeout', () => {
    expect(built(() => new IamEngine({ adapter: seed(), mode: 'production' })).warnings).toEqual([])
    expect(
      built(() => new IamEngine({ adapter: seed(), adapterTimeoutMs: 50, hookTimeoutMs: 50, mode: 'production' }))
        .warnings,
    ).toEqual([])
  })

  it('says it once per option per process', () => {
    built(() => new IamEngine({ adapter: seed(), adapterTimeoutMs: 0, mode: 'production' }))
    const second = built(() => new IamEngine({ adapter: seed(), adapterTimeoutMs: 0, mode: 'production' }))

    expect(second.warnings).toEqual([])
  })

  it('warns about a real difference: the timeout is what makes a hung store deny', async () => {
    const guarded = built(
      () => new IamEngine({ adapter: hungAdapter(), adapterTimeoutMs: 50, mode: 'production' }),
    ).value
    const unguarded = built(
      () => new IamEngine({ adapter: hungAdapter(), adapterTimeoutMs: 0, mode: 'production' }),
    ).value

    expect({
      guarded: await outcomeOf(guarded.can('u1', 'read', POST)),
      unguarded: await outcomeOf(unguarded.can('u1', 'read', POST)),
    }).toEqual({ guarded: 'settled', unguarded: 'HUNG' })
  })

  it('and about hookTimeoutMs, where a hook that never settles takes the evaluation with it', async () => {
    const engine = built(
      () =>
        new IamEngine({
          adapter: seed(),
          hooks: { beforeEvaluate: (req) => new Promise<typeof req>(() => {}) },
          hookTimeoutMs: 0,
          mode: 'production',
        }),
    ).value

    expect(await outcomeOf(engine.can('u1', 'read', POST))).toBe('HUNG')
  })
})
