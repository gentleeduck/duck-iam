/** Adapters inject this per request; every store call takes one. A single-tenant app leaves it undefined. */
export interface TenantContext {
  tenantId?: string
}
