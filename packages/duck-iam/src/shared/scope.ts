/**
 * Adapter-boundary guard for the scope argument of `assignRole` / `revokeRole`; omit the scope for a global grant.
 * NOTE: neither `''` nor `'*'` means global, since assignments match scope literally; a `'lookup'` still accepts `'*'`
 * so rows written before this guard can be revoked.
 *
 * @param adapter - Adapter name for the error message, e.g. `'memory'`.
 * @param scope   - The scope argument as the caller passed it.
 * @param intent  - `'grant'` (default) for a new assignment; `'lookup'` for a row that may already exist.
 * @throws When `scope` is the empty string, or `'*'` on a `'grant'`.
 */
export function iamAssertAssignableScope(adapter: string, scope: unknown, intent: 'grant' | 'lookup' = 'grant'): void {
  if (scope === '') {
    throw new Error(`[@gentleduck/iam:${adapter}] scope must not be an empty string; omit it for a global assignment`)
  }
  if (scope === '*' && intent === 'grant') {
    throw new Error(
      `[@gentleduck/iam:${adapter}] scope must not be "*"; a scoped assignment is matched literally, so this grant ` +
        'would be stored and answer only a request whose own scope is the string "*". Omit the scope for a global ' +
        'assignment.',
    )
  }
}
