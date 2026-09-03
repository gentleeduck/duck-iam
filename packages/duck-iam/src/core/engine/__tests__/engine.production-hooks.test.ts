import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'
import type { IamEngineTypes } from '../engine.types'

/**
 * `afterEvaluate` and `onDeny` were documented and implemented as development
 * only, which put the audit and alerting hooks in exactly the mode nobody runs
 * in production. They now fire in both. Production cannot produce the same
 * object - the compiled table erases policy identity by design - so it hands
 * over a verdict-only `IDecision`, and these tests pin both halves: that the
 * hooks fire, and that consumers are not told a `policy` they cannot have.
 */

type Action = 'read' | 'delete'
type ResourceType = 'post'
type RoleId = 'viewer'

const viewer: AccessControl.IRole<Action, ResourceType, RoleId> = {
  id: 'viewer',
  name: 'Viewer',
  permissions: [{ action: 'read', resource: 'post' }],
}

function adapter() {
  return new IamMemoryAdapter<Action, ResourceType, RoleId>({
    assignments: { u1: ['viewer'] },
    roles: [viewer],
  })
}

describe('afterEvaluate / onDeny fire in production too', () => {
  it('afterEvaluate fires on an allow', async () => {
    const seen: AccessControl.IDecision[] = []
    const engine = new IamEngine<Action, ResourceType, RoleId>({
      adapter: adapter(),
      hooks: { afterEvaluate: (_req, d) => void seen.push(d) },
      mode: 'production',
    })

    expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' })).toBe(true)
    expect(seen).toHaveLength(1)
    expect(seen[0]).toMatchObject({ allowed: true, effect: 'allow' })
  })

  it('onDeny fires on a deny, and afterEvaluate sees the same decision', async () => {
    const seen: AccessControl.IDecision[] = []
    const denied: AccessControl.IDecision[] = []
    const engine = new IamEngine<Action, ResourceType, RoleId>({
      adapter: adapter(),
      hooks: { afterEvaluate: (_req, d) => void seen.push(d), onDeny: (_req, d) => void denied.push(d) },
      mode: 'production',
    })

    expect(await engine.can('u1', 'delete', { attributes: {}, type: 'post' })).toBe(false)
    expect(denied).toHaveLength(1)
    expect(denied[0]).toMatchObject({ allowed: false, effect: 'deny' })
    expect(seen[0]).toBe(denied[0])
  })

  it('onDeny does not fire on an allow', async () => {
    const onDeny = vi.fn()
    const engine = new IamEngine<Action, ResourceType, RoleId>({
      adapter: adapter(),
      hooks: { onDeny },
      mode: 'production',
    })

    await engine.can('u1', 'read', { attributes: {}, type: 'post' })
    expect(onDeny).not.toHaveBeenCalled()
  })

  it('the production decision is verdict-only, and says so rather than claiming a policy', async () => {
    let decision: AccessControl.IDecision | undefined
    const engine = new IamEngine<Action, ResourceType, RoleId>({
      adapter: adapter(),
      hooks: { afterEvaluate: (_req, d) => void (decision = d) },
      mode: 'production',
    })

    await engine.can('u1', 'read', { attributes: {}, type: 'post' })

    expect(decision?.reason).toMatch(/production mode/)
    expect(decision?.policy).toBeUndefined()
    expect(decision?.rule).toBeUndefined()
    expect(decision?.duration).toBeGreaterThanOrEqual(0)
    expect(decision?.timestamp).toBeGreaterThan(0)
  })

  it('development still hands over the full decision, with a real reason', async () => {
    let decision: AccessControl.IDecision | undefined
    const engine = new IamEngine<Action, ResourceType, RoleId, string, 'development'>({
      adapter: adapter(),
      hooks: { afterEvaluate: (_req, d) => void (decision = d) },
      mode: 'development',
    })

    await engine.can('u1', 'read', { attributes: {}, type: 'post' })

    expect(decision?.allowed).toBe(true)
    expect(decision?.reason).not.toMatch(/production mode/)
  })

  it('a throwing hook cannot rewrite the production verdict', async () => {
    const consoleErr = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const engine = new IamEngine<Action, ResourceType, RoleId>({
        adapter: adapter(),
        hooks: {
          afterEvaluate: () => {
            throw new Error('audit-down')
          },
        },
        mode: 'production',
      })

      expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' })).toBe(true)
      expect(consoleErr).toHaveBeenCalled()
    } finally {
      consoleErr.mockRestore()
    }
  })
})

describe('configuration defaults', () => {
  /** The private fields the engine records its own configuration in. */
  function config(engine: unknown): { _mode: string; _maxConcurrentSubjectLoads: number } {
    if (engine === null || typeof engine !== 'object') throw new TypeError('not an engine')
    if (!('_mode' in engine) || !('_maxConcurrentSubjectLoads' in engine)) throw new TypeError('not an engine')
    const mode = engine._mode
    const max = engine._maxConcurrentSubjectLoads
    if (typeof mode !== 'string' || typeof max !== 'number') throw new TypeError('not an engine')
    return { _maxConcurrentSubjectLoads: max, _mode: mode }
  }

  it("mode defaults to 'production', so an unconfigured engine is the fast one", () => {
    expect(config(new IamEngine({ adapter: new IamMemoryAdapter() }))._mode).toBe('production')
  })

  it('an explicit mode still wins', () => {
    expect(config(new IamEngine({ adapter: new IamMemoryAdapter(), mode: 'development' }))._mode).toBe('development')
  })

  it('maxConcurrentSubjectLoads defaults to a real bound rather than unbounded', () => {
    expect(config(new IamEngine({ adapter: new IamMemoryAdapter() }))._maxConcurrentSubjectLoads).toBe(512)
  })

  it('0 still means unbounded, for callers who want the old behaviour back', () => {
    const engine = new IamEngine({ adapter: new IamMemoryAdapter(), maxConcurrentSubjectLoads: 0 })
    expect(config(engine)._maxConcurrentSubjectLoads).toBe(0)
  })
})

describe('setInvalidator attaches after construction', () => {
  /** Minimal in-process invalidator: publish fans out to every subscriber. */
  function bus() {
    const handlers = new Set<(e: IamEngineTypes.IInvalidateEvent) => void>()
    return {
      handlers,
      invalidator: {
        publish: (event: IamEngineTypes.IInvalidateEvent) => {
          for (const h of handlers) h(event)
        },
        subscribe: (handler: (e: IamEngineTypes.IInvalidateEvent) => void) => {
          handlers.add(handler)
          return () => void handlers.delete(handler)
        },
      },
    }
  }

  it('an engine built without one still subscribes when given one later', () => {
    const { handlers, invalidator } = bus()
    const engine = new IamEngine({ adapter: new IamMemoryAdapter() })
    expect(handlers.size).toBe(0)

    engine.setInvalidator(invalidator)
    expect(handlers.size).toBe(1)
  })

  it('a remote roles event reaching the new subscription clears the role cache', async () => {
    const { invalidator } = bus()
    const engine = new IamEngine({ adapter: new IamMemoryAdapter(), cacheTTL: 60_000 })
    engine.setInvalidator(invalidator)

    await engine.admin.saveRole({ id: 'reader', name: 'Reader', permissions: [] })
    await engine.getEffectiveRoles('u1')
    const before = engine.stats.get().roles.misses

    invalidator.publish({ kind: 'roles' })
    await engine.getEffectiveRoles('u1')

    expect(engine.stats.get().roles.misses).toBeGreaterThan(before)
  })

  it('replacing one detaches the old subscription first', () => {
    const first = bus()
    const second = bus()
    const engine = new IamEngine({ adapter: new IamMemoryAdapter(), invalidator: first.invalidator })
    expect(first.handlers.size).toBe(1)

    engine.setInvalidator(second.invalidator)

    expect(first.handlers.size).toBe(0)
    expect(second.handlers.size).toBe(1)
  })

  it('null detaches without attaching anything', () => {
    const { handlers, invalidator } = bus()
    const engine = new IamEngine({ adapter: new IamMemoryAdapter(), invalidator })

    engine.setInvalidator(null)

    expect(handlers.size).toBe(0)
  })

  it('rejects a malformed invalidator instead of silently never invalidating', () => {
    const engine = new IamEngine({ adapter: new IamMemoryAdapter() })

    // The guard is a runtime one: TypeScript already refuses these, which is
    // exactly why only a JS or config-driven caller ever reaches it. A missing
    // `subscribe` would otherwise surface much later, as remote invalidations
    // that never arrive.
    expect(() => engine.setInvalidator(JSON.parse('{"publish":1}'))).toThrow(TypeError)
    expect(() => engine.setInvalidator(JSON.parse('{"publish":1,"subscribe":2}'))).toThrow(TypeError)
    expect(() => engine.setInvalidator(JSON.parse('"not-an-object"'))).toThrow(TypeError)
  })
})
