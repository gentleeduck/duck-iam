import type { TenantContext } from './tenant.types'

/** Reaches every tenant; see `TenantContext.allTenants`. */
export const ALL_TENANTS: TenantContext = Object.freeze({ allTenants: true } as const)
