/** Per-request tenant scope via AsyncLocalStorage. */

import { AsyncLocalStorage } from 'node:async_hooks'
import type { AuthTenantContext } from './types/context'

const _als = new AsyncLocalStorage<AuthTenantContext>()

/** Run `fn` with `tenantId` bound; `authCurrentTenant()` resolves to the value across awaits. */
export function authWithTenant<T>(tenantId: string | undefined, fn: () => T | Promise<T>): T | Promise<T> {
  return _als.run(tenantId !== undefined ? { tenantId } : {}, fn)
}

/** Read the current tenant scope; prefer {@link authResolveTenant} for caller-supplied overrides. */
export function authCurrentTenant(): AuthTenantContext | undefined {
  return _als.getStore()
}

/**
 * Pick the effective `AuthTenantContext` for a call. Explicit
 * caller-supplied context wins over the ALS ambient (so callers can
 * still scope a single call across a different tenant - `authWithTenant`
 * is a default, not a fence).
 */
export function authResolveTenant(explicit?: AuthTenantContext): AuthTenantContext {
  if (explicit !== undefined && explicit.tenantId !== undefined) return explicit
  return _als.getStore() ?? {}
}
