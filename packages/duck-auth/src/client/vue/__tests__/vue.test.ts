/**
 * `vue` is not installed in this monorepo's dev tree, so the Vue
 * client lazily resolves it via `require('vue')`. These tests cover:
 *   - the module surface (factory + composables exist)
 *   - the missing-vue error path (require throws)
 * Full reactive-state integration is exercised by consumer apps that
 * actually install `vue`.
 */

import { describe, expect, it } from 'vitest'
import { createAuthVuePlugin, useSession, useSignIn, useSignOut } from '../index'

describe('Vue client (no `vue` installed)', () => {
  it('exposes the composable surface as functions', () => {
    expect(typeof createAuthVuePlugin).toBe('function')
    expect(typeof useSession).toBe('function')
    expect(typeof useSignIn).toBe('function')
    expect(typeof useSignOut).toBe('function')
  })

  it('createAuthVuePlugin returns a plugin shape without touching `vue`', () => {
    const plugin = createAuthVuePlugin({ baseUrl: '/auth' })
    expect(typeof plugin.install).toBe('function')
  })

  it('install() surfaces a clear error when `vue` is missing', () => {
    const plugin = createAuthVuePlugin({ baseUrl: '/auth' })
    const fakeApp = { provide: () => fakeApp }
    expect(() => plugin.install(fakeApp)).toThrow(/vue/)
  })
})
