/** The tenant a store call is held to. Naming none reaches only the rows with no tenant, which in an app without
 *  tenants is every row, so a call that forgets its tenant finds nothing of a tenant's. */
export interface TenantContext {
  tenantId?: string
  /** Every tenant at once, for the engine's own work across them: erasure, export, ending every session. */
  allTenants?: true
}
