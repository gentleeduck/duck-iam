/**
 * `vue` is not installed in this monorepo's dev tree, so the Vue
 * client lazily resolves it via `require('vue')`. These tests cover:
 *   - the module surface (factory + composables exist)
 *   - the missing-vue error path (require throws)
 * Full reactive-state integration is exercised by consumer apps that
 * actually install `vue`.
 */

import { describe, expect, it } from 'vitest'
import { authCreateVuePlugin, authUseSession, authUseSignIn, authUseSignOut } from '../index'

describe('Vue client (no `vue` installed)', () => {
  it('exposes the composable surface as functions', () => {
    expect(typeof authCreateVuePlugin).toBe('function')
    expect(typeof authUseSession).toBe('function')
    expect(typeof authUseSignIn).toBe('function')
    expect(typeof authUseSignOut).toBe('function')
  })

  it('authCreateVuePlugin returns a plugin shape without touching `vue`', () => {
    const plugin = authCreateVuePlugin({ baseUrl: '/auth' })
    expect(typeof plugin.install).toBe('function')
  })

  it('install() surfaces a clear error when `vue` is missing', () => {
    const plugin = authCreateVuePlugin({ baseUrl: '/auth' })
    const fakeApp = { provide: () => fakeApp }
    expect(() => plugin.install(fakeApp)).toThrow(/vue/)
  })
})
