import type { AccessControl } from '../core/types'
import { validatePolicy, validateRole } from '../core/validate'

/**
 * Throws on any error-level issue, so every adapter refuses a malformed row at write time.
 * NOTE: the read-path checks stay; they catch rows that reached the store another way (a migration, a hand edit).
 */
function assertValid(
  adapter: string,
  kind: string,
  row: unknown,
  issues: readonly { type: string; message: string }[],
): void {
  const errors = issues.filter((i) => i.type === 'error')
  if (errors.length === 0) return
  const messages = errors.map((e) => e.message).join('; ')
  throw new Error(`[@gentleduck/iam:${adapter}] refusing to save invalid ${kind} "${rowLabel(row)}": ${messages}`)
}

/** The row's own string `id` for the error message, or a stand-in when it has none. */
function rowLabel(row: unknown): string {
  if (typeof row !== 'object' || row === null || !('id' in row)) return '<no id>'
  return typeof row.id === 'string' ? row.id : String(row.id)
}

/**
 * Refuses a policy the read path would drop.
 *
 * @param adapter - Adapter name for the error message, e.g. `'memory'`.
 * @param policy  - The policy as the caller passed it; `unknown` because it checks untrusted input.
 * @throws When {@link validatePolicy} reports any error-level issue.
 */
export function iamAssertSavablePolicy(adapter: string, policy: unknown): void {
  assertValid(adapter, 'policy', policy, validatePolicy(policy).issues)
}

/**
 * Refuses a role the read path would drop.
 *
 * @param adapter - Adapter name for the error message, e.g. `'memory'`.
 * @param role    - The role as the caller passed it; `unknown` because it checks untrusted input.
 * @throws When {@link validateRole} reports any error-level issue.
 */
export function iamAssertSavableRole(adapter: string, role: unknown): void {
  assertValid(adapter, 'role', role, validateRole(role).issues)
}

/** A row the caller can no longer reach: a store that keeps their object serves later edits to it. */
export function iamCloneRow<T>(row: T): T {
  return structuredClone(row)
}

/**
 * Copy of the policy in the one shape every adapter round-trips: `version` defaults to `1` (the SQL default),
 * absent optional keys stay absent (not `undefined`), and fields outside {@link AccessControl.IPolicy} are dropped.
 */
export function iamNormalizePolicy<TAction extends string, TResource extends string, TRole extends string>(
  policy: AccessControl.IPolicy<TAction, TResource, TRole>,
): AccessControl.IPolicy<TAction, TResource, TRole> {
  const src = iamCloneRow(policy)
  return {
    id: src.id,
    name: src.name,
    ...(src.description === undefined ? {} : { description: src.description }),
    version: src.version ?? 1,
    algorithm: src.algorithm,
    rules: src.rules,
    ...(src.targets === undefined ? {} : { targets: src.targets }),
  }
}

/**
 * The error every adapter raises for a policy row it cannot read; the row is never skipped.
 * SECURITY: fails closed; unlike an allow-only role row, a dropped policy may be the deny. Reads fail until repaired.
 */
export function iamUnreadablePolicy(adapter: string, id: string, detail: string): Error {
  return new Error(
    `[@gentleduck/iam:${adapter}] policy "${id}" cannot be read and will not be skipped - a dropped policy may be ` +
      `the one that denies. Repair or delete the row. (${detail})`,
  )
}
