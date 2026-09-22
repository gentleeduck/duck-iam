/**
 * Reserved action / resource type meaning "this request could not be mapped"; nothing named `'unknown'` can be granted.
 * SECURITY: `authorize` and `permissions` refuse it before any policy, since a `'*'` rule matches any sentinel string.
 */
export const IAM_RESERVED_REFUSAL = 'unknown'

/** True when `value` is the reserved refusal token; callers test the request's action and resource type. */
export function iamIsReservedRefusal(value: unknown): boolean {
  return value === IAM_RESERVED_REFUSAL
}
