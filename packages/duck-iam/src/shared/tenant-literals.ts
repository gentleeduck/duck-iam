import type { IamRequest } from '../core/types'

// The one place a stored or requested string is taken as a member of the caller's literal unions; no runtime check can
// prove it. Callers must first check for a non-empty string (`iamRequireStringField` does for a request body).

/** A role id from a store or a request, taken at the caller's declared `TRole`. */
export function iamAsRoleLiteral<TRole extends string>(value: string): TRole {
  return value as TRole
}

/** A scope id from a store or a request, taken at the caller's declared `TScope`. */
export function iamAsScopeLiteral<TScope extends string>(value: string): TScope {
  return value as TScope
}

/** An action derived from a request, taken at the caller's declared `TAction` (for the method-derived default). */
export function iamAsActionLiteral<TAction extends string>(value: string): TAction {
  return value as TAction
}

/** A resource type derived from a request path, at the caller's `TResource` (for the path-derived default). */
export function iamAsResourceLiteral<TResource extends string>(value: string): TResource {
  return value as TResource
}

/** The whole resource descriptor at the caller's `TResource`; only `type` is narrowed, the rest is copied as-is. */
export function iamResourceAtCallerType<TResource extends string>(
  resource: IamRequest.IResource,
): IamRequest.IResource<TResource> {
  return { ...resource, type: iamAsResourceLiteral<TResource>(resource.type) }
}
