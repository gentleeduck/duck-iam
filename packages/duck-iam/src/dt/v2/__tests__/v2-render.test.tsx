import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import React from 'react'
import { renderToString } from 'react-dom/server'
import { afterEach, beforeAll, describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../../core/engine/engine'
import type { Explain } from '../../../core/explain/explain.types'
import type { AccessControl } from '../../../core/types'
import { iamCreateMetricsAggregator } from '../../../observability/metrics'
import { iamCreateFlowRecorder } from '../../lib/flow'
import type { IamIDevtoolsEngine } from '../../lib/types'
import { IamDevtoolsInnerV2 } from '../iam-devtools-inner-v2'
import { IamDevtoolsV2 } from '../iam-devtools-v2'
import { IamDecisionInspectorV2 } from '../panels/decision'
import { IamFlowPanelV2 } from '../panels/flow'
import { IamMetricsPanelV2 } from '../panels/metrics'
import { IamPoliciesPanelV2 } from '../panels/policies'
import { IamRolesPanelV2 } from '../panels/roles'
import { IamSubjectsPanelV2 } from '../panels/subjects'
import { IamTraceTreeV2 } from '../panels/trace'

/**
 * v2's counterpart to `dt/__tests__/panels-render.test.tsx`, and it exists for
 * the same reason: `./dt/v2` exports all eight components individually, so
 * each is a supported entry point, and a component that reads the engine
 * wrongly fails at render.
 *
 * v2 adds a failure mode v1 does not have. Its markup comes from duck-ui
 * components resolved out of `@gentleduck/registry-ui` - a package whose own
 * API can move under us, and whose `exports` map points at TypeScript source
 * rather than a build. A rename there is a runtime throw here, invisible to
 * `tsc` only if nothing renders. So these render against a real `IamEngine`
 * over a real `IamMemoryAdapter`, with the real duck-ui components, not stubs.
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

const readPosts: AccessControl.IPolicy<Action, ResourceType, RoleId> = {
  algorithm: 'deny-overrides',
  id: 'read-posts',
  name: 'Read posts',
  rules: [{ actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 1, resources: ['post'] }],
}

function engineIn(mode: 'development' | 'production'): IamIDevtoolsEngine {
  return new IamEngine<Action, ResourceType, RoleId, Scope, 'development' | 'production'>({
    adapter: new IamMemoryAdapter<Action, ResourceType, RoleId, Scope>({
      assignments: { u1: ['org-reader'] },
      policies: [readPosts],
      roles: [orgReader],
    }),
    cacheTTL: 0,
    mode,
  })
}

const originalNodeEnv = process.env.NODE_ENV

afterEach(() => {
  if (originalNodeEnv === undefined) delete process.env.NODE_ENV
  else process.env.NODE_ENV = originalNodeEnv
})

/** A real trace, so the tree is rendered against the shape it actually receives. */
let trace: Explain.IResult

beforeAll(async () => {
  trace = await engineIn('development').explain('u1', 'read', { attributes: {}, type: 'post' })
})

/** Everything `./dt/v2` exports that can be mounted on its own. */
function everyExport(): readonly (readonly [string, () => React.ReactElement])[] {
  return [
    ['IamDecisionInspectorV2', () => <IamDecisionInspectorV2 engine={engineIn('development')} />],
    ['IamFlowPanelV2', () => <IamFlowPanelV2 flow={iamCreateFlowRecorder()} />],
    ['IamMetricsPanelV2', () => <IamMetricsPanelV2 engine={engineIn('development')} />],
    ['IamPoliciesPanelV2', () => <IamPoliciesPanelV2 engine={engineIn('development')} />],
    ['IamRolesPanelV2', () => <IamRolesPanelV2 engine={engineIn('development')} />],
    ['IamSubjectsPanelV2', () => <IamSubjectsPanelV2 engine={engineIn('development')} />],
    ['IamTraceTreeV2', () => <IamTraceTreeV2 result={trace} />],
    ['IamDevtoolsInnerV2', () => <IamDevtoolsInnerV2 engine={engineIn('development')} />],
    ['IamDevtoolsV2', () => <IamDevtoolsV2 engine={engineIn('development')} initialIsOpen />],
  ] as const
}

describe('every v2 export renders against a real engine and real duck-ui', () => {
  it.each(everyExport())('%s renders without throwing', (_name, element) => {
    process.env.NODE_ENV = 'development'
    expect(() => renderToString(element())).not.toThrow()
  })

  it.each(everyExport())('%s produces markup rather than an empty string', (_name, element) => {
    // Anti-vacuity: "did not throw" is also true of a component that renders
    // nothing at all, which is what a mis-fired guard looks like.
    process.env.NODE_ENV = 'development'
    expect(renderToString(element()).length).toBeGreaterThan(0)
  })

  it('the trace the tree renders is a real engine result, not an empty one', () => {
    expect(trace.policies.length).toBeGreaterThan(0)
    expect(trace.subject.roles).toContain('org-reader')
    expect(trace.decision.allowed).toBe(true)
  })
})

/**
 * Every v2 component that can stand alone is its own root, marked with
 * `data-iam-dt-v2`.
 *
 * v1 gets this guarantee by requiring `.iam-dt` on its outermost node, because
 * that is where its tokens are declared. v2's reason is different but the
 * requirement is the same: the attribute is the only handle a host has for
 * finding, hiding or overriding the devtool from its own CSS, and a panel that
 * renders without one is unaddressable.
 */
function standalonePanels(): readonly (readonly [string, () => React.ReactElement])[] {
  return everyExport().filter(([name]) => name !== 'IamDevtoolsV2')
}

describe('a v2 panel mounted on its own is its own root', () => {
  it.each(standalonePanels())('%s marks its outermost element', (_name, element) => {
    process.env.NODE_ENV = 'development'
    expect(renderToString(element()).slice(0, 300)).toMatch(/^<[a-z]+ [^>]*data-iam-dt-v2=""/)
  })
})

/** Every v2 component handed the engine, and the four states the guard must get right. */
function enginePanels(): readonly (readonly [string, (mode: 'development' | 'production') => React.ReactElement])[] {
  return [
    ['IamDecisionInspectorV2', (m) => <IamDecisionInspectorV2 engine={engineIn(m)} />],
    ['IamMetricsPanelV2', (m) => <IamMetricsPanelV2 engine={engineIn(m)} />],
    ['IamPoliciesPanelV2', (m) => <IamPoliciesPanelV2 engine={engineIn(m)} />],
    ['IamRolesPanelV2', (m) => <IamRolesPanelV2 engine={engineIn(m)} />],
    ['IamSubjectsPanelV2', (m) => <IamSubjectsPanelV2 engine={engineIn(m)} />],
    ['IamDevtoolsInnerV2', (m) => <IamDevtoolsInnerV2 engine={engineIn(m)} />],
    ['IamDevtoolsV2', (m) => <IamDevtoolsV2 engine={engineIn(m)} initialIsOpen />],
  ] as const
}

describe('v2 carries the same production guard as v1', () => {
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
    // The control. Without it every assertion above is satisfied by a
    // component that never renders at all.
    process.env.NODE_ENV = 'development'
    expect(renderToString(element('development')).length).toBeGreaterThan(0)
  })
})

/**
 * The list above is written by hand and cannot notice a panel added next year.
 * This can: any v2 panel module that reaches for the engine has to call the
 * guard, read out of the source rather than the export list.
 */
describe('no v2 panel can reach the engine without the guard', () => {
  it('every v2 panel module that uses the engine calls isDevtoolsAllowed', () => {
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
    expect(offenders, 'these v2 panels read the engine with no production guard').toEqual([])
    // Anti-vacuity: an empty sweep would pass the assertion above.
    expect(checked, 'the sweep matched no v2 panel at all').toBeGreaterThanOrEqual(5)
  })
})

describe('the v2 shell renders the pieces a user has to be able to reach', () => {
  it('shows the dock control, the close control and a tablist', () => {
    process.env.NODE_ENV = 'development'
    const html = renderToString(<IamDevtoolsV2 engine={engineIn('development')} initialIsOpen />)
    expect(html).toContain('role="dialog"')
    expect(html).toContain('role="tablist"')
    expect(html).toContain('aria-label="Close devtools"')
    expect(html).toContain('aria-label="Resize devtools panel"')
  })

  it('gives the resize separator the full value triple its role requires', () => {
    // A focusable `separator` is the window-splitter widget: it announces a
    // position, so it has to announce the scale that position sits on.
    process.env.NODE_ENV = 'development'
    const html = renderToString(<IamDevtoolsV2 engine={engineIn('development')} initialIsOpen />)
    expect(html).toMatch(/aria-valuemin="\d+"/)
    expect(html).toMatch(/aria-valuemax="\d+"/)
    expect(html).toMatch(/aria-valuenow="\d+"/)
  })

  it('renders the launcher instead when it is closed', () => {
    process.env.NODE_ENV = 'development'
    const html = renderToString(<IamDevtoolsV2 engine={engineIn('development')} />)
    expect(html).toContain('aria-label="Open duck-iam devtools"')
    expect(html).not.toContain('role="dialog"')
  })

  it('says so rather than breaking when no flow recorder is wired', () => {
    process.env.NODE_ENV = 'development'
    const html = renderToString(<IamDevtoolsInnerV2 engine={engineIn('development')} />)
    expect(html).toContain('No flow recorder wired')
  })
})

/** A recorder holding one allow and one deny, so the table has rows to draw. */
function recorderWithTraffic() {
  const flow = iamCreateFlowRecorder()
  flow.record({ action: 'read', allowed: true, durationMs: 1.5, resource: 'post', resourceId: 'p1', subjectId: 'u1' })
  flow.record({
    action: 'delete',
    allowed: false,
    durationMs: 0.4,
    reason: 'no rule',
    resource: 'post',
    subjectId: 'u2',
  })
  return flow
}

/**
 * The duck-ui components v2 was rebuilt onto have to reach the page, not just
 * the import graph.
 *
 * `v2-contract.test.tsx` proves the imports exist; a component can be imported
 * and never rendered, or rendered only down a branch no test takes. These
 * assert the markup those components produce, from the states that produce it.
 */
describe('the duck-ui components v2 is built on actually reach the markup', () => {
  it('draws the flow log as a real table with its columns named', () => {
    process.env.NODE_ENV = 'development'
    const html = renderToString(<IamFlowPanelV2 flow={recorderWithTraffic()} />)
    expect(html).toContain('data-slot="table"')
    expect(html).toContain('data-slot="table-head"')
    for (const column of ['verdict', 'request', 'subject', 'when', 'took']) {
      expect(html, `the flow table lost its ${column} column`).toContain(`>${column}<`)
    }
    // The rows themselves, not just the frame.
    expect(html).toContain('data-slot="table-row"')
    expect(html).toContain('allow: read on post for u1')
  })

  it('gives the flow verdict filters real switches', () => {
    process.env.NODE_ENV = 'development'
    const html = renderToString(<IamFlowPanelV2 flow={recorderWithTraffic()} />)
    expect(html).toContain('data-slot="switch"')
    expect(html).toContain('role="switch"')
  })

  it('draws telemetry rates on a progressbar that announces its value', () => {
    process.env.NODE_ENV = 'development'
    const metrics = iamCreateMetricsAggregator()
    metrics.record({
      action: 'read',
      allowed: true,
      durationMs: 1,
      failOpen: false,
      mode: 'development',
      resource: 'post',
      subjectId: 'u1',
    })
    metrics.record({
      action: 'read',
      allowed: false,
      durationMs: 2,
      failOpen: false,
      mode: 'development',
      resource: 'post',
      subjectId: 'u2',
    })
    const html = renderToString(<IamMetricsPanelV2 engine={engineIn('development')} metrics={metrics} />)
    expect(html).toContain('data-slot="progress"')
    expect(html).toContain('role="progressbar"')
    // A bar with no accessible name is one of several unlabelled bars.
    expect(html).toContain('aria-label="allow rate"')
    expect(html).toMatch(/aria-valuenow="\d+"/)
  })

  it('puts sections in cards and separates them with real separators', () => {
    // Telemetry, because its sections render with no selection made - a list
    // panel shows only its empty state until something is picked.
    process.env.NODE_ENV = 'development'
    const html = renderToString(<IamMetricsPanelV2 engine={engineIn('development')} />)
    expect(html).toContain('data-card=""')
    expect(html).toContain('data-slot="card-title"')
    expect(html).toContain('data-slot="separator"')
  })

  it('keeps duck-ui’s tab pills rather than flattening them into a bar', () => {
    process.env.NODE_ENV = 'development'
    const html = renderToString(<IamDevtoolsInnerV2 engine={engineIn('development')} />)
    expect(html).toContain('data-slot="tabs-list"')
    expect(html).toContain('data-slot="tabs-trigger"')
    // duck-ui's own list styling, which an earlier version overrode away.
    // Attribute order is React's, so the class is matched back to the slot
    // rather than forward from it.
    expect(html).toMatch(/class="[^"]*rounded-md bg-muted[^"]*"[^>]*data-slot="tabs-list"/)
  })

  it('labels the shell’s close control with the key that also does it', () => {
    process.env.NODE_ENV = 'development'
    const html = renderToString(<IamDevtoolsV2 engine={engineIn('development')} initialIsOpen />)
    expect(html).toContain('data-slot="kbd"')
  })
})
