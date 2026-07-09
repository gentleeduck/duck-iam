/**
 * Per-request tenant scope. Framework adapters inject this via AsyncLocalStorage;
 * stores receive it on every call. Apps without multi-tenancy leave tenantId undefined.
 */
export interface TenantContext {
  tenantId?: string
}
