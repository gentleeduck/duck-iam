import type { IamPrimitives } from '../core/types'

/**
 * Adapter-boundary guard for `setSubjectAttributes`. A non-object `attrs`
 * (a string, say) would otherwise spread into per-character keys and corrupt
 * the bag; every adapter rejects it with the same message.
 */
export function iamAssertAttributesParam(
  adapter: string,
  subjectId: string,
  attrs: unknown,
): asserts attrs is IamPrimitives.Attributes {
  if (typeof attrs !== 'object' || attrs === null || Array.isArray(attrs)) {
    const got = attrs === null ? 'null' : Array.isArray(attrs) ? 'array' : typeof attrs
    throw new Error(`[@gentleduck/iam:${adapter}] attributes for "${subjectId}" must be a plain object (got ${got})`)
  }
}
