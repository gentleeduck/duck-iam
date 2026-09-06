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
    engine: new IamEngine<Action, ResourceType, RoleId, Scope>({ adapter, cacheTTL: 0, mode: 'development' }),
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

/** No `mode` at all - the engine defaults to development. */
function defaultEngine() {
  const adapter = new IamMemoryAdapter<Action, ResourceType, RoleId, Scope>({ roles: [orgReader] })
  return { adapter, engine: new IamEngine<Action, ResourceType, RoleId, Scope>({ adapter, cacheTTL: 0 }) }
}

const originalNodeEnv = process.env.NODE_ENV

afterEach(() => {
  if (originalNodeEnv === undefined) delete process.env.NODE_ENV
  else process.env.NODE_ENV = originalNodeEnv
})

/**
 * The guard reads the engine's mode off a TypeScript-`private` `_mode` field by
 * name. Every existing guard test hands it a hand-rolled object carrying that
 * name, so the whole suite would keep passing if the real engine renamed the
 * field, stopped setting it, or moved it behind an accessor - and devtools
 * would then see "no mode signal" from a production engine. Under
 * `NODE_ENV=production` that still blocks; with `NODE_ENV` unset or
 * `development` it is the difference between blocked and an unauthenticated
 * role-assignment UI.
 */
describe('the devtools guard reads the mode of a real engine', () => {
  it('blocks a production engine when NODE_ENV says nothing', () => {
    delete process.env.NODE_ENV
    expect(isDevtoolsAllowed(prodEngine().engine)).toBe(false)
  })

  it('allows a development engine when NODE_ENV says nothing', () => {
    delete process.env.NODE_ENV
    // The positive case is what pins the field name: if `_mode` stopped being
    // readable this would fall through to the default block and fail here,
    // rather than silently agreeing with the negative cases above.
    expect(isDevtoolsAllowed(devEngine().engine)).toBe(true)
  })

  it('allows the default-mode engine, which is development', () => {
    delete process.env.NODE_ENV
    expect(isDevtoolsAllowed(defaultEngine().engine)).toBe(true)
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

/**
 * `IamIDevtoolsEngine` is a hand-written narrowing of the engine, and nothing
 * checked the two against each other. It declared four parameters for
 * `can`/`explain` where the engine takes five, so the Decision Inspector's
 * `scope` box could not reach `scope` and the compiler had nothing to object
 * to - the panel folded it into the environment bag instead, where nothing
 * reads it.
 */
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

    // What the panel used to send. The trace comes back confidently DENY with
    // its own `request.scope` reading `undefined`, so an operator debugging a
    // scoped grant is shown a denial for a request the engine allows.
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

/**
 * `formatAttrValue` runs inside a React render, and `JSON.stringify` throws on
 * exactly the two kinds of value a caller can put in a request attribute bag.
 * The throw took out the trace panel, or the whole host app where there was no
 * error boundary.
 */
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

  // Control: an ordinary object still renders, so the marker is not the answer
  // to everything.
  it('still renders an ordinary object', () => {
    expect(formatAttrValue({ a: 1 })).toBe('{"a":1}')
  })
})

/**
 * The panel reads the engine's cache counters at first render, so the drift was
 * not a latent typing nit: `engine.stats` is an object and the panel called it,
 * which threw out of a `useState` initializer and took the devtools panel down
 * the moment an operator opened Telemetry against a real engine.
 */
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
