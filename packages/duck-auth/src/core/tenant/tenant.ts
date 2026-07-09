/** Per-request tenant scope via AsyncLocalStorage. */

import { AsyncLocalStorage } from 'node:async_hooks'
import type { TenantContext } from '../types/infra'

const _als = new AsyncLocalStorage<TenantContext>()

/** Run `fn` with `tenantId` bound; `currentTenant()` resolves to the value across awaits. */
export function withTenant<T>(tenantId: string | undefined, fn: () => T | Promise<T>): T | Promise<T> {
  return _als.run(tenantId !== undefined ? { tenantId } : {}, fn)
}

/** Read the current tenant scope; prefer {@link resolveTenant} for caller-supplied overrides. */
export function currentTenant(): TenantContext | undefined {
  return _als.getStore()
}

/**
 * Pick the effective `TenantContext` for a call. Explicit
 * caller-supplied context wins over the ALS ambient (so callers can
 * still scope a single call across a different tenant - `withTenant`
 * is a default, not a fence).
 */
export function resolveTenant(explicit?: TenantContext): TenantContext {
  if (explicit !== undefined && explicit.tenantId !== undefined) return explicit
  return _als.getStore() ?? {}
}
