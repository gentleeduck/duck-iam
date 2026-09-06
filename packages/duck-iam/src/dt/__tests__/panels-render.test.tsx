import React from 'react'
import { renderToString } from 'react-dom/server'
import { afterEach, beforeAll, describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../adapters/memory'
import { IamEngine } from '../../core/engine/engine'
import type { Explain } from '../../core/explain/explain.types'
import type { AccessControl } from '../../core/types'
import { iamCreateFlowRecorder } from '../lib/flow'
import type { IamIDevtoolsEngine } from '../lib/types'
import { IamDecisionInspector } from '../panels/decision'
import { IamFlowPanel } from '../panels/flow'
import { IamMetricsPanel } from '../panels/metrics'
import { IamPoliciesPanel } from '../panels/policies'
import { IamRolesPanel } from '../panels/roles'
import { IamSubjectsPanel } from '../panels/subjects'
import { IamTraceTree } from '../panels/trace-tree'

/**
 * `package.json` publishes `./dt` and `src/dt/index.ts` exports all seven
 * panels individually, so each one is a supported entry point. Only
 * `IamMetricsPanel` was ever rendered by a test - and it earned that test by
 * throwing on first render against a real engine, which took the whole devtools
 * overlay down the moment an operator opened Telemetry.
 *
 * That is a bug class, not an incident: a panel that reads the engine wrongly
 * fails at render, and six of the seven had nothing that would render them.
 * These do, against a real `IamEngine` over a real `IamMemoryAdapter` rather
 * than a hand-shaped stub, because a stub cannot disagree with the engine.
 *
 * The guard blocks below cover every panel handed an engine. `IamSubjectsPanel`
 * is the one that *writes* the most - `assignRole`, `revokeRole`,
 * `setAttributes` - and it was the first to carry `isDevtoolsAllowed` itself,
 * because importing it directly, which the export invites, put an
 * unauthenticated role-assignment UI on screen with no guard anywhere in its
 * path. The same route was still open on the readers, which is what the blocks
 * below now close.
 */
type Action = 'read'
type ResourceType = 'post'
type RoleId = 'org-reader'
type Scope = 'org-a'

const orgReader: AccessControl.IRole<Action, ResourceType, RoleId, Scope> = {
  id: 'org-reader',
  name: 'Org Reader',
  permissions: [{ action: 'read', resource: 'post' }],
}

/**
 * A stored policy, so the panels have rows to render and `explain()` produces a
 * trace with a policy in it. A panel that renders an empty list correctly can
 * still throw on the first row it is handed.
 */
const readPosts: AccessControl.IPolicy<Action, ResourceType, RoleId> = {
  algorithm: 'deny-overrides',
  id: 'read-posts',
  name: 'Read posts',
  rules: [{ actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 1, resources: ['post'] }],
}

function engineIn(mode: 'development' | 'production'): IamIDevtoolsEngine {
  const adapter = new IamMemoryAdapter<Action, ResourceType, RoleId, Scope>({
    assignments: { u1: ['org-reader'] },
    policies: [readPosts],
    roles: [orgReader],
  })
  return new IamEngine<Action, ResourceType, RoleId, Scope, 'development' | 'production'>({
    adapter,
    cacheTTL: 0,
    mode,
  })
}

const originalNodeEnv = process.env.NODE_ENV

afterEach(() => {
  if (originalNodeEnv === undefined) delete process.env.NODE_ENV
  else process.env.NODE_ENV = originalNodeEnv
})

/**
 * A real trace, produced by the engine rather than written by hand, so
 * `IamTraceTree` is rendered against the shape it actually receives.
 */
let trace: Explain.IResult

beforeAll(async () => {
  const engine = engineIn('development')
  trace = await engine.explain('u1', 'read', { attributes: {}, type: 'post' })
})

/**
 * Every panel with the props its own signature asks for. `flow` and
 * `trace-tree` take a recorder and a result rather than an engine, so the list
 * is element factories rather than a component array.
 */
function readOnlyPanels(): readonly (readonly [string, () => React.ReactElement])[] {
  return [
    ['IamDecisionInspector', () => <IamDecisionInspector engine={engineIn('development')} />],
    ['IamFlowPanel', () => <IamFlowPanel flow={iamCreateFlowRecorder()} />],
    ['IamMetricsPanel', () => <IamMetricsPanel engine={engineIn('development')} />],
    ['IamPoliciesPanel', () => <IamPoliciesPanel engine={engineIn('development')} />],
    ['IamRolesPanel', () => <IamRolesPanel engine={engineIn('development')} />],
    ['IamTraceTree', () => <IamTraceTree result={trace} />],
  ] as const
}

describe('every exported panel renders against a real engine', () => {
  it.each(readOnlyPanels())('%s renders without throwing', (_name, element) => {
    process.env.NODE_ENV = 'development'
    expect(() => renderToString(element())).not.toThrow()
  })

  it.each(readOnlyPanels())('%s produces markup rather than an empty string', (_name, element) => {
    // Anti-vacuity: "did not throw" is also true of a component that renders
    // nothing at all, which is exactly what a mis-fired guard looks like.
    process.env.NODE_ENV = 'development'
    expect(renderToString(element()).length).toBeGreaterThan(0)
  })

  it('the trace the tree renders is a real engine result, not an empty one', () => {
    // Otherwise the render above proves only that the empty case is safe.
    expect(trace.policies.length).toBeGreaterThan(0)
    expect(trace.subject.roles).toContain('org-reader')
    expect(trace.decision.allowed).toBe(true)
  })
})

/**
 * Every panel that is handed the engine, and the four states the guard has to
 * get right for each of them.
 *
 * This started as one block for `IamSubjectsPanel`, because it is the panel
 * that writes. But `isDevtoolsAllowed`'s own docblock says it blocks so "the
 * policy/role/subject **readers** cannot leak into raw-browser bundles
 * (CWE-200)", and two of those three readers did not call it: `IamPoliciesPanel`
 * hands back the entire policy corpus through `engine.admin.listPolicies()`,
 * `IamRolesPanel` the whole role catalog, and `IamDecisionInspector` is an
 * oracle that will answer `explain()` for any subject, action and resource
 * typed into it. Each is exported individually under `./dt`, so each is a
 * supported way to put that on a production screen with no check in its path -
 * blocked through `IamDevtools`, wide open through its own export.
 *
 * `IamMetricsPanel` is here too, and it retires the "only panel that writes"
 * framing: its Reset button calls `engine.stats.reset()`.
 */
function enginePanels(): readonly (readonly [string, (mode: 'development' | 'production') => React.ReactElement])[] {
  return [
    ['IamDecisionInspector', (m) => <IamDecisionInspector engine={engineIn(m)} />],
    ['IamMetricsPanel', (m) => <IamMetricsPanel engine={engineIn(m)} />],
    ['IamPoliciesPanel', (m) => <IamPoliciesPanel engine={engineIn(m)} />],
    ['IamRolesPanel', (m) => <IamRolesPanel engine={engineIn(m)} />],
    ['IamSubjectsPanel', (m) => <IamSubjectsPanel engine={engineIn(m)} />],
  ] as const
}

describe('every panel that touches the engine carries the production guard itself', () => {
  it.each(enginePanels())('%s renders nothing for a production-mode engine', (_name, element) => {
    process.env.NODE_ENV = 'development'
    expect(renderToString(element('production'))).toBe('')
  })

  it.each(enginePanels())('%s renders nothing under NODE_ENV=production', (_name, element) => {
    process.env.NODE_ENV = 'production'
    expect(renderToString(element('development'))).toBe('')
  })

  it.each(enginePanels())('%s renders nothing when neither side signals development', (_name, element) => {
    // Absence of a signal is not permission.
    delete process.env.NODE_ENV
    expect(renderToString(element('production'))).toBe('')
  })

  it.each(enginePanels())('%s renders for a development engine under NODE_ENV=development', (_name, element) => {
    // The control. Without it every assertion above is satisfied by a panel
    // that never renders at all.
    process.env.NODE_ENV = 'development'
    expect(renderToString(element('development')).length).toBeGreaterThan(0)
  })
})

/**
 * The list above is written by hand, so it cannot notice a panel added next
 * year. This can: any panel module that reaches for the engine has to call the
 * guard, and the check reads the source rather than the export list.
 *
 * `flow` and `trace-tree` are not exempted by name - they are simply not
 * matched, because they take a recorder and a result and never touch an engine.
 * If either ever does, this fails until it is guarded.
 */
describe('no panel can reach the engine without the guard', () => {
  it('every panel module that uses the engine calls isDevtoolsAllowed', async () => {
    const { readdirSync, readFileSync } = await import('node:fs')
    const { join } = await import('node:path')
    const dir = join(import.meta.dirname, '..', 'panels')
    const offenders: string[] = []
    let checked = 0
    for (const file of readdirSync(dir)) {
      if (!file.endsWith('.tsx')) continue
      const src = readFileSync(join(dir, file), 'utf8')
      if (!/\bengine\./.test(src)) continue
      checked++
      if (!src.includes('isDevtoolsAllowed(engine)')) offenders.push(file)
    }
    expect(offenders, 'these panels read the engine with no production guard').toEqual([])
    // Anti-vacuity: an empty sweep would pass the assertion above while
    // checking nothing - a renamed directory, or a regex that stopped matching.
    expect(checked, 'the sweep matched no panel at all').toBeGreaterThanOrEqual(5)
  })
})
