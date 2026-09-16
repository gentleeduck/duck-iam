import React from 'react'
import { renderToString } from 'react-dom/server'
import { afterEach, describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../adapters/memory'
import { IamEngine } from '../../core/engine/engine'
import type { AccessControl } from '../../core/types'
import { formatAttrValue } from '../lib/format'
import { isDevtoolsAllowed } from '../lib/guard'
import type { IamIDevtoolsEngine } from '../lib/types'
import { IamMetricsPanel } from '../panels/metrics'

type Action = 'read'
type ResourceType = 'post'
type RoleId = 'org-reader'
type Scope = 'org-a' | 'org-b'

const orgReader: AccessControl.IRole<Action, ResourceType, RoleId, Scope> = {
  id: 'org-reader',
  name: 'Org Reader',
  permissions: [{ action: 'read', resource: 'post' }],
  scope: 'org-a',
}

function devEngine() {
  const adapter = new IamMemoryAdapter<Action, ResourceType, RoleId, Scope>({ roles: [orgReader] })
  return {
    adapter,
    engine: new IamEngine<Action, ResourceType, RoleId, Scope, 'development'>({
      adapter,
      cacheTTL: 0,
      mode: 'development',
    }),
  }
}

function prodEngine() {
  const adapter = new IamMemoryAdapter<Action, ResourceType, RoleId, Scope>({ roles: [orgReader] })
  return {
    adapter,
    engine: new IamEngine<Action, ResourceType, RoleId, Scope, 'production'>({
      adapter,
      cacheTTL: 0,
      mode: 'production',
    }),
  }
}

/** No `mode`, so the engine defaults to production. */
function defaultEngine() {
  const adapter = new IamMemoryAdapter<Action, ResourceType, RoleId, Scope>({ roles: [orgReader] })
  return { adapter, engine: new IamEngine<Action, ResourceType, RoleId, Scope>({ adapter, cacheTTL: 0 }) }
}

const originalNodeEnv = process.env.NODE_ENV

afterEach(() => {
  if (originalNodeEnv === undefined) delete process.env.NODE_ENV
  else process.env.NODE_ENV = originalNodeEnv
})

// The guard reads the TS-private `_mode` by name; mocks cannot catch the real engine renaming it.
// If it went unreadable, `NODE_ENV=development` would open devtools over a production engine.
describe('the devtools guard reads the mode of a real engine', () => {
  it('blocks a production engine when NODE_ENV says nothing', () => {
    delete process.env.NODE_ENV
    expect(isDevtoolsAllowed(prodEngine().engine)).toBe(false)
  })

  it('allows a development engine when NODE_ENV says nothing', () => {
    delete process.env.NODE_ENV
    // The positive case pins the field name: an unreadable `_mode` falls through to the default block and fails here.
    expect(isDevtoolsAllowed(devEngine().engine)).toBe(true)
  })

  it('blocks the default-mode engine, which is production', () => {
    delete process.env.NODE_ENV
    // Devtools need an explicit `mode: 'development'`; forgetting `mode` fails closed.
    expect(isDevtoolsAllowed(defaultEngine().engine)).toBe(false)
  })

  it('blocks a production engine even under NODE_ENV=development', () => {
    process.env.NODE_ENV = 'development'
    expect(isDevtoolsAllowed(prodEngine().engine)).toBe(false)
  })

  it('blocks a development engine under NODE_ENV=production', () => {
    process.env.NODE_ENV = 'production'
    expect(isDevtoolsAllowed(devEngine().engine)).toBe(false)
  })
})

// `IamIDevtoolsEngine` is hand-written, so pin it to the real engine, including `scope` as the 5th argument.
describe('the devtools engine interface matches the engine it narrows', () => {
  it('accepts a real engine', () => {
    const { engine } = devEngine()
    const narrowed: IamIDevtoolsEngine = engine
    expect(typeof narrowed.explain).toBe('function')
  })

  it('carries scope through to the engine as the 5th argument', async () => {
    const { adapter, engine } = devEngine()
    await adapter.assignRole('user-1', 'org-reader', 'org-a')
    const narrowed: IamIDevtoolsEngine = engine

    const trace = await narrowed.explain('user-1', 'read', { attributes: {}, type: 'post' }, {}, 'org-a')

    expect(trace.request.scope).toBe('org-a')
    expect(trace.subject.scopedRolesApplied).toContain('org-reader')
    expect(trace.decision.allowed).toBe(true)
  })

  it('ignores a scope smuggled into the environment bag', async () => {
    const { adapter, engine } = devEngine()
    await adapter.assignRole('user-1', 'org-reader', 'org-a')
    const narrowed: IamIDevtoolsEngine = engine

    // A scope in the environment is ignored, so the trace denies a request the engine allows with a real scope.
    const trace = await narrowed.explain('user-1', 'read', { attributes: {}, type: 'post' }, { scope: 'org-a' })

    expect(trace.request.scope).toBeUndefined()
    expect(trace.subject.scopedRolesApplied).toEqual([])
    expect(trace.decision.allowed).toBe(false)
  })

  it('does not treat a wrong scope as a match', async () => {
    const { adapter, engine } = devEngine()
    await adapter.assignRole('user-1', 'org-reader', 'org-a')
    const narrowed: IamIDevtoolsEngine = engine

    const trace = await narrowed.explain('user-1', 'read', { attributes: {}, type: 'post' }, {}, 'org-b')

    expect(trace.request.scope).toBe('org-b')
    expect(trace.decision.allowed).toBe(false)
  })
})

// `formatAttrValue` runs inside a React render, so it must not throw on values `JSON.stringify` rejects.
describe('the trace formatter never throws on a value it cannot serialise', () => {
  it('renders a marker for a self-referential object', () => {
    const cyclic: Record<string, unknown> = { name: 'a' }
    cyclic.self = cyclic
    expect(formatAttrValue(cyclic)).toBe('(unserializable)')
  })

  it('renders a marker for a cycle reached through an array', () => {
    const arr: unknown[] = ['a']
    arr.push({ back: arr })
    expect(formatAttrValue(arr)).toBe('["a", (unserializable)]')
  })

  it('renders a marker for a BigInt', () => {
    expect(formatAttrValue(BigInt(1))).toBe('(unserializable)')
  })

  it('renders a marker for a value whose toJSON throws', () => {
    const hostile = {
      toJSON() {
        throw new Error('boom')
      },
    }
    expect(formatAttrValue(hostile)).toBe('(unserializable)')
  })

  it('renders a marker for a function, which stringifies to undefined', () => {
    expect(formatAttrValue(() => undefined)).toBe('(unserializable)')
  })

  // Control: an ordinary object still renders.
  it('still renders an ordinary object', () => {
    expect(formatAttrValue({ a: 1 })).toBe('{"a":1}')
  })
})

// The panel reads `engine.stats.get()` in a `useState` initializer, so a shape mismatch throws on first render.
describe('the telemetry panel reads a real engine', () => {
  it('renders the engine cache counters', () => {
    const { engine } = devEngine()
    const html = renderToString(<IamMetricsPanel engine={engine} />)
    // Five caches, named by the engine's own snapshot.
    expect(html).toContain('policies')
    expect(html).toContain('subjects')
    expect(html).toContain('Caches (5)')
  })

  it('renders the same counters the engine reports', async () => {
    const { adapter, engine } = devEngine()
    await adapter.assignRole('user-1', 'org-reader', 'org-a')
    await engine.can('user-1', 'read', { attributes: {}, type: 'post' }, undefined, 'org-a')

    const snapshot = engine.stats.get()
    expect(Object.keys(snapshot).length).toBe(5)
    expect(renderToString(<IamMetricsPanel engine={engine} />)).toContain(`Caches (${Object.keys(snapshot).length})`)
  })
})
