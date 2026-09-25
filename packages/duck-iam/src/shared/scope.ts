import { throwIamError } from '../core/errors'

/**
 * Adapter-boundary guard for every scope an adapter writes: `assignRole`, `revokeRole`, `updateAssignmentScope`
 * (both ends) and drizzle's `assignRoleMany` / `revokeRoleMany`. Omit the scope for a global grant.
 * NOTE: neither `''` nor `'*'` means global, since assignments match scope literally; a `'lookup'` still accepts `'*'`
 * so rows written before this guard can be revoked.
 *
 * @param adapter - Adapter name for the error message, e.g. `'memory'`.
 * @param scope   - The scope argument as the caller passed it.
 * @param intent  - `'grant'` (default) for a new assignment; `'lookup'` for a row that may already exist.
 * @throws When `scope` is the empty string, or `'*'` on a `'grant'`.
 */
export function iamAssertAssignableScope(adapter: string, scope: unknown, intent: 'grant' | 'lookup' = 'grant'): void {
  if (scope === '') throwIamError('IAM_SCOPE_INVALID', { adapter, reason: 'empty' })
  if (scope === '*' && intent === 'grant') throwIamError('IAM_SCOPE_INVALID', { adapter, reason: 'wildcard-on-grant' })
}
