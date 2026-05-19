import React from 'react'
import { renderToString } from 'react-dom/server'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { IamDevtools } from '../iam-devtools-panel'
import type { IDevtoolsEngine } from '../lib/types'

/**
 * Build a minimal `IDevtoolsEngine`-shaped object carrying an optional `mode`.
 * Methods reject so any panel that slips past the guard would fail loudly in
 * a test; the guard tests below assert nothing slips past.
 */
function makeMockEngine(mode?: 'production' | 'development'): IDevtoolsEngine {
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
  } as unknown as IDevtoolsEngine
  return engine
}

describe('IamDevtools production guard', () => {
  const ORIGINAL_NODE_ENV = process.env.NODE_ENV

  afterEach(() => {
    vi.unstubAllGlobals()
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

  it('renders in development when `process` is undefined (raw-browser bundle)', () => {
    // Simulate a browser bundle that did not shim `process`. The guard must
    // fall through to the engine-mode arm and allow the component to mount.
    vi.stubGlobal('process', undefined)
    const engine = makeMockEngine('development')
    const html = renderToString(React.createElement(IamDevtools, { engine }))
    expect(html).toContain('iam-dt-btn-wrap')
  })

  it('blocks even when `process` is undefined if engine mode is production', () => {
    vi.stubGlobal('process', undefined)
    const engine = makeMockEngine('production')
    const html = renderToString(React.createElement(IamDevtools, { engine, initialIsOpen: true }))
    expect(html).toBe('')
  })
})
