import { AsyncLocalStorage } from 'node:async_hooks'
import type { TenantContext } from '../tenant/tenant.types'

const _als = new AsyncLocalStorage<TenantContext>()

/** Binds `tenantId` for `fn`, across awaits. */
export function withTenant<T>(tenantId: string | undefined, fn: () => T | Promise<T>): T | Promise<T> {
  return _als.run(tenantId !== undefined ? { tenantId } : {}, fn)
}

/** Read the current tenant scope; prefer {@link resolveTenant} for caller-supplied overrides. */
export function currentTenant(): TenantContext | undefined {
  return _als.getStore()
}

/** An explicit context beats the ambient one, so a single call can still cross tenants: {@link withTenant}
 *  is a default, not a fence. */
export function resolveTenant(explicit?: TenantContext): TenantContext {
  if (explicit !== undefined && explicit.tenantId !== undefined) return explicit
  return _als.getStore() ?? {}
}
