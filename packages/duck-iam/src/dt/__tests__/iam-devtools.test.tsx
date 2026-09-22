import React from 'react'
import { renderToString } from 'react-dom/server'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { IamDevtools } from '../iam-devtools-panel'
import type { IamIDevtoolsEngine } from '../lib/types'

/** `vi.stubGlobal` fallback for bun's test runner, which lacks it; tracks stubs so `afterEach` can restore them. */
const _stubbedGlobals: Array<{ key: PropertyKey; prior: unknown; had: boolean }> = []
function stubGlobalCompat(key: string, value: unknown): void {
  const helper = (vi as { stubGlobal?: (k: string, v: unknown) => void }).stubGlobal
  if (typeof helper === 'function') {
    helper(key, value)
    return
  }
  const g = globalThis as Record<string, unknown>
  _stubbedGlobals.push({ key, prior: g[key], had: Object.hasOwn(g, key) })
  g[key] = value
}
function unstubAllCompat(): void {
  const u = (vi as { unstubAllGlobals?: () => void }).unstubAllGlobals
  if (typeof u === 'function') {
    u()
    return
  }
  const g = globalThis as Record<string, unknown>
  while (_stubbedGlobals.length) {
    const e = _stubbedGlobals.pop()!
    if (e.had) g[e.key as string] = e.prior
    else delete g[e.key as string]
  }
}

/** Mock engine with an optional `mode`; `can`, `explain` and `admin.*` throw, so a guard bypass fails loudly. */
function makeMockEngine(mode?: 'production' | 'development'): IamIDevtoolsEngine {
  const trap = (label: string) => () => {
    throw new Error(`engine.${label} should not be called when devtools is guarded`)
  }
  const engine = {
    mode,
    can: trap('can'),
    explain: trap('explain'),
    stats: { get: () => ({}), reset: () => {} },
    admin: {
      listPolicies: trap('admin.listPolicies'),
      listRoles: trap('admin.listRoles'),
      getPolicy: trap('admin.getPolicy'),
      getRole: trap('admin.getRole'),
      assignRole: trap('admin.assignRole'),
      revokeRole: trap('admin.revokeRole'),
      setAttributes: trap('admin.setAttributes'),
      getAttributes: trap('admin.getAttributes'),
      export: trap('admin.export'),
    },
  } as unknown as IamIDevtoolsEngine
  return engine
}

describe('IamDevtools production guard', () => {
  const ORIGINAL_NODE_ENV = process.env.NODE_ENV

  afterEach(() => {
    unstubAllCompat()
    process.env.NODE_ENV = ORIGINAL_NODE_ENV
  })

  it('renders nothing when engine reports mode "production"', () => {
    process.env.NODE_ENV = 'test'
    const engine = makeMockEngine('production')
    const html = renderToString(React.createElement(IamDevtools, { engine, initialIsOpen: true }))
    expect(html).toBe('')
  })

  it('renders nothing when process.env.NODE_ENV === "production"', () => {
    process.env.NODE_ENV = 'production'
    const engine = makeMockEngine('development')
    const html = renderToString(React.createElement(IamDevtools, { engine, initialIsOpen: true }))
    expect(html).toBe('')
  })

  it('renders a container in development mode', () => {
    process.env.NODE_ENV = 'development'
    const engine = makeMockEngine('development')
    const html = renderToString(React.createElement(IamDevtools, { engine, hideButton: true }))
    // Closed with `hideButton` renders nothing either way; the launcher check below is the real assertion.
    expect(typeof html).toBe('string')
    // With the launcher visible we get a wrapper div; verify that path too.
    const open = renderToString(React.createElement(IamDevtools, { engine }))
    expect(open).toContain('iam-dt-btn-wrap')
  })

  it('renders when `process` is undefined and engine mode is development (raw-browser bundle)', () => {
    stubGlobalCompat('process', undefined)
    const engine = makeMockEngine('development')
    const html = renderToString(React.createElement(IamDevtools, { engine }))
    expect(html).toContain('iam-dt-btn-wrap')
  })

  it('blocks even when `process` is undefined if engine mode is production', () => {
    stubGlobalCompat('process', undefined)
    const engine = makeMockEngine('production')
    const html = renderToString(React.createElement(IamDevtools, { engine, initialIsOpen: true }))
    expect(html).toBe('')
  })

  it('BLOCKS when `process` is undefined AND engine mode is unset (default-block)', () => {
    // No positive development signal on either side means the panel never mounts.
    stubGlobalCompat('process', undefined)
    const engine = makeMockEngine(undefined)
    const html = renderToString(React.createElement(IamDevtools, { engine, initialIsOpen: true }))
    expect(html).toBe('')
  })

  it('renders when NODE_ENV is development even if engine mode is unset', () => {
    process.env.NODE_ENV = 'development'
    const engine = makeMockEngine(undefined)
    const html = renderToString(React.createElement(IamDevtools, { engine }))
    expect(html).toContain('iam-dt-btn-wrap')
  })

  it('BLOCKS when NODE_ENV is "test" and engine mode is unset', () => {
    // NODE_ENV=test is not a development signal.
    process.env.NODE_ENV = 'test'
    const engine = makeMockEngine(undefined)
    const html = renderToString(React.createElement(IamDevtools, { engine, initialIsOpen: true }))
    expect(html).toBe('')
  })
})
