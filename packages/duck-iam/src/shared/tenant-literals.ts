/**
 * The one place this package admits that a runtime string is not a proven
 * member of a caller's role or scope union.
 *
 * `getSubjectRoles` promises `Promise<TRole[]>` because the consumer named
 * those literals in `createIam`, but the values come from a store that holds
 * plain strings, or from an admin request body. No runtime check can close
 * that gap: the legitimate values are whatever the calling app declared, and
 * nothing in the package holds that list at the point of the read.
 *
 * So the narrowing is real and unavoidable. What was avoidable was having it
 * eighteen times across five adapters and four server integrations as a bare
 * `as TRole`, indistinguishable at a glance from the laundering casts that used
 * to sit in front of the row validators. Routing it through these two functions
 * makes the boundary greppable and gives it one docstring instead of none.
 *
 * Callers must have checked that the value is a non-empty string first; these
 * do not. `iamRequireStringField` in `server/generic` is that check for a
 * request body.
 */

/** A role id from a store or a request, taken at the caller's declared `TRole`. */
export function iamAsRoleLiteral<TRole extends string>(value: string): TRole {
  return value as TRole
}

/** A scope id from a store or a request, taken at the caller's declared `TScope`. */
export function iamAsScopeLiteral<TScope extends string>(value: string): TScope {
  return value as TScope
}
