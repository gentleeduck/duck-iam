import React from 'react'
import { renderToString } from 'react-dom/server'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { IamDevtools } from '../iam-devtools-panel'
import type { IamIDevtoolsEngine } from '../lib/types'

/**
 * Compatibility shim: bun's test runner doesn't ship `vi.stubGlobal`. Track
 * stubbed keys ourselves so the afterEach block can restore them when the
 * vitest helpers are absent.
 */
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

/**
 * Build a minimal `IamIDevtoolsEngine`-shaped object carrying an optional `mode`.
 * Methods reject so any panel that slips past the guard would fail loudly in
 * a test; the guard tests below assert nothing slips past.
 */
function makeMockEngine(mode?: 'production' | 'development'): IamIDevtoolsEngine {
  const trap = (label: string) => () => {
    throw new Error(`engine.${label} should not be called when devtools is guarded`)
  }
  const engine = {
    mode,
    can: trap('can'),
    explain: trap('explain'),
    stats: () => ({}),
    resetStats: () => {},
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
    // hideButton suppresses the floating launcher; the panel itself is unmounted
    // until `open` flips. A non-production guard still allows the component to
    // mount (returning the empty fragment for closed state), so output must not
    // be the bare `null` we'd get from the guard.
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
    // Previous fail-open path: no NODE_ENV + no engine.mode -> rendered.
    // New default-block path: absence of any positive `development` signal
    // means the panel never mounts.
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
    // Tests deliberately set NODE_ENV=test - without an engine positive
    // signal the guard must still block.
    process.env.NODE_ENV = 'test'
    const engine = makeMockEngine(undefined)
    const html = renderToString(React.createElement(IamDevtools, { engine, initialIsOpen: true }))
    expect(html).toBe('')
  })
})
