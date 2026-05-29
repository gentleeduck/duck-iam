/**
 * Per-request tenant scope via AsyncLocalStorage.
 *
 * Framework adapters call `withTenant(tenantId, fn)` once per request
 * (or per job iteration / CLI invocation); downstream code reads the
 * current tenant via `currentTenant()` instead of threading the
 * `TenantContext` arg through every facet call.
 *
 * Stores still accept an explicit `TenantContext` for backwards
 * compatibility; consumers using ALS pass `undefined` and the store
 * resolves via the ambient.
 */

import { AsyncLocalStorage } from 'node:async_hooks'
import type { TenantContext } from './types/context'

const _als = new AsyncLocalStorage<TenantContext>()

/**
 * Run `fn` with `tenantId` bound to the current async chain. Every
 * async operation spawned inside `fn` (and every code path it awaits
 * into) observes `currentTenant()` returning the supplied value.
 *
 * Pass `undefined` to enter the global / no-tenant scope explicitly -
 * useful in tests + CLI tools where the lack of a tenant should be
 * audit-visible rather than implicit.
 *
 * @example
 * ```ts
 * app.use((req, _res, next) => {
 *   const tenantId = req.headers['x-tenant-id'] ?? undefined
 *   withTenant(tenantId, () => next())
 * })
 *
 * // Job runner
 * for (const tenant of tenants) {
 *   await withTenant(tenant.id, () => runDailyJobsFor(tenant))
 * }
 * ```
 */
export function withTenant<T>(tenantId: string | undefined, fn: () => T | Promise<T>): T | Promise<T> {
  return _als.run(tenantId !== undefined ? { tenantId } : {}, fn)
}

/**
 * Read the current tenant scope, or `undefined` when no `withTenant`
 * wrapper is active. Library code should prefer to resolve the
 * effective scope via {@link resolveTenant} which also considers a
 * caller-supplied explicit `TenantContext`.
 */
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
