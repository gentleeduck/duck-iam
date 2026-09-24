import { IamError, throwIamValidationFailed } from '../core/errors'
import type { AccessControl } from '../core/types'
import type { IamValidate } from '../core/validate'
import { validatePolicy, validateRole } from '../core/validate'

/**
 * Throws on any error-level issue, so every adapter refuses a malformed row at write time.
 * NOTE: the read-path checks stay; they catch rows that reached the store another way (a migration, a hand edit).
 */
function assertValid(
  adapter: string,
  kind: 'policy' | 'role',
  row: unknown,
  issues: readonly IamValidate.IIssue[],
): void {
  void adapter // kept for signature compatibility with both call sites; no longer needed once the message is gone
  void row
  if (issues.some((issue) => issue.type === 'error')) throwIamValidationFailed(kind, issues)
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
 * SECURITY: fails closed; a dropped policy may be the deny.
 */
export function iamUnreadablePolicy(adapter: string, id: string, detail: string): IamError {
  return new IamError('IAM_UNREADABLE_POLICY', { adapter, policyId: id, detail })
}

/**
 * The same, for a role row. A role's `permissions` only grant, but the role *id* is also what a deny selects on -
 * `policy.targets.roles`, and `subject.roles contains "x"` in a rule condition. Dropping the definition drops the
 * id out of `resolveEffectiveRoles`, so those denies stop applying while grants from the subject's other roles
 * stand: the verdict moves from deny to allow.
 * SECURITY: the witnesses this used to rely on do not cover that. `reportUnreachableRoleTargets` sees
 * `targets.roles` only, and `reportUndefinedAssignedRole` fires only when the subject holds the id *directly* -
 * neither says anything when the id was reached through `inherits` and the deny is written as a condition.
 */
export function iamUnreadableRole(adapter: string, id: string, detail: string): IamError {
  return new IamError('IAM_UNREADABLE_ROLE', { adapter, roleId: id, detail })
}

/**
 * The role rewritten without the `inherits` entry naming `deletedId`, or `null` when it never named it.
 * SECURITY: an orphan edge re-attaches if the id is recreated, exactly as an orphan grant would.
 */
export function iamRoleWithoutInherit<
  TAction extends string,
  TResource extends string,
  TRole extends string,
  TScope extends string,
>(
  role: AccessControl.IRole<TAction, TResource, TRole, TScope>,
  deletedId: string,
): AccessControl.IRole<TAction, TResource, TRole, TScope> | null {
  const inherits = role.inherits
  if (!Array.isArray(inherits) || !inherits.includes(deletedId)) return null
  const kept = inherits.filter((parent) => parent !== deletedId)
  const { inherits: _dropped, ...rest } = role
  // An absent `inherits` is how every writer spells "inherits nothing"; an empty array is not the same row.
  return kept.length === 0 ? rest : { ...rest, inherits: kept }
}
