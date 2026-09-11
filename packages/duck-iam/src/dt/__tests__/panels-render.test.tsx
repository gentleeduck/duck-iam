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

// Every exported panel renders against a real `IamEngine` (a stub cannot disagree with the engine),
// and every panel handed an engine carries the production guard itself.
type Action = 'read'
type ResourceType = 'post'
type RoleId = 'org-reader'
type Scope = 'org-a'

const orgReader: AccessControl.IRole<Action, ResourceType, RoleId, Scope> = {
  id: 'org-reader',
  name: 'Org Reader',
  permissions: [{ action: 'read', resource: 'post' }],
}

/** A stored policy, so panels render real rows and `explain()` yields a trace with a policy in it. */
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

/** A real engine trace, so `IamTraceTree` renders the shape it actually receives. */
let trace: Explain.IResult

beforeAll(async () => {
  const engine = engineIn('development')
  trace = await engine.explain('u1', 'read', { attributes: {}, type: 'post' })
})

/** Element factories, since `flow` and `trace-tree` take a recorder or a result instead of an engine. */
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
    // Anti-vacuity: an empty render also "does not throw", and that is what a mis-fired guard produces.
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

// Each engine panel is importable on its own and exposes policies, roles, an `explain()` oracle or
// `stats.reset()`, so each must block by itself.
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
    // Control: without it, a panel that never renders satisfies every assertion above.
    process.env.NODE_ENV = 'development'
    expect(renderToString(element('development')).length).toBeGreaterThan(0)
  })
})

// Catches future panels: any `panels/` module that touches `engine.` must call the guard.
// `flow` and `trace-tree` are not exempt by name; they just never touch an engine.
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
    // Guard against an empty sweep passing vacuously.
    expect(checked, 'the sweep matched no panel at all').toBeGreaterThanOrEqual(5)
  })
})
