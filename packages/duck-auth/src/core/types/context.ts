/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

/**
 * Per-request tenant scope. Framework adapters inject this via AsyncLocalStorage;
 * stores receive it on every call. Apps without multi-tenancy leave tenantId undefined.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface TenantContext {
  tenantId?: string
}
