import type { IamRequest } from '../core/types'

/** A subject's unscoped (global) role IDs from their raw assignment entries, deduplicated. */
export function iamUnscopedRoleIds<TRole extends string>(
  entries: readonly { role: TRole; scope?: unknown }[],
): TRole[] {
  return [...new Set(entries.filter((e) => e.scope == null).map((e) => e.role))]
}

/** A subject's scoped `(role, scope)` assignment entries only, from their raw assignment list. */
export function iamScopedRoleEntries<TRole extends string, TScope extends string>(
  entries: readonly { role: TRole; scope?: TScope }[],
): IamRequest.IScopedRole<TRole, TScope>[] {
  const hasScope = (e: { role: TRole; scope?: TScope }): e is { role: TRole; scope: TScope } => e.scope != null
  return entries.filter(hasScope).map((e) => ({ role: e.role, scope: e.scope }))
}

/** Adds `(roleId, scope)` to `entries` in place, unless that exact pair is already present. */
export function iamAddAssignmentIfAbsent<TRole extends string, TScope extends string>(
  entries: { role: TRole; scope?: TScope }[],
  roleId: TRole,
  scope?: TScope,
): void {
  if (!entries.some((e) => e.role === roleId && e.scope === scope)) entries.push({ role: roleId, scope })
}

/**
 * `entries` with every `(roleId, scope)` match removed; omitting `scope` removes every assignment for the role.
 * `roleId` takes a plain `string` (not `TRole`) so {@link iamPruneRoleAssignments} can share this without a cast.
 */
export function iamFilterOutRoleAssignment<TRole extends string, TScope extends string>(
  entries: readonly { role: TRole; scope?: TScope }[],
  roleId: string,
  scope: TScope | undefined,
): { role: TRole; scope?: TScope }[] {
  return scope === undefined
    ? entries.filter((e) => e.role !== roleId)
    : entries.filter((e) => !(e.role === roleId && e.scope === scope))
}

/** `entries` with every assignment of `roleId` removed, or `null` when none were present (nothing to write back). */
export function iamPruneRoleAssignments<TRole extends string, TScope extends string>(
  entries: readonly { role: TRole; scope?: TScope }[],
  roleId: string,
): { role: TRole; scope?: TScope }[] | null {
  const kept = iamFilterOutRoleAssignment(entries, roleId, undefined)
  return kept.length === entries.length ? null : kept
}
