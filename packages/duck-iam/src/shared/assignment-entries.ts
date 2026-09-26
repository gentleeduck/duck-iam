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
