/**
 * The request values that mean "this request could not be mapped, refuse it".
 *
 * The framework adapters turn an HTTP request into an `(action, resource)` pair,
 * and some requests cannot be mapped: an unmapped method, or a path that this
 * layer and the router downstream would read differently. Both cases used to be
 * expressed by handing the engine a sentinel *string* and relying on it to
 * match no policy - `IAM_UNKNOWN_ACTION` was documented as "must match no
 * permission and be denied", `IAM_UNKNOWN_RESOURCE` as "matches no policy
 * target, so the request is denied".
 *
 * Neither was true. `'*'` matches every string, sentinels included, so a
 * wildcard rule - `.on('*').of('*')`, the ordinary shape of an admin role -
 * turned both refusals back into allows. The traversal guard that refuses to
 * resolve `/posts/../admin/secret` handed the engine `type: 'unknown'`, and any
 * subject with a wildcard grant was allowed, on exactly the path built to
 * refuse.
 *
 * A string cannot carry a denial, so the denial moved into the engine: this
 * token is reserved, and `authorize` and `permissions` refuse it before
 * consulting any policy. That makes the refusal true by construction rather
 * than by hoping no policy is broad enough to match it.
 *
 * The token keeps its historical value so the exported constants and anything
 * comparing against them are unchanged. The cost of reserving it is that a
 * resource type or action genuinely named `'unknown'` can no longer be granted;
 * both constants have always been documented as sentinels, and denying them is
 * what they were always said to do.
 */
export const IAM_RESERVED_REFUSAL = 'unknown'

/**
 * True when a request names the reserved refusal token in a position that
 * decides the request - the action, or the resource type.
 *
 * Deliberately not exhaustive over the request: this is about the two fields
 * the adapters derive from an untrusted method and path.
 */
export function iamIsReservedRefusal(value: unknown): boolean {
  return value === IAM_RESERVED_REFUSAL
}
