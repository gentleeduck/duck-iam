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

/** True for a JSON scalar: `string | number | boolean | null`. */
function isScalar(value: unknown): value is IamPrimitives.Scalar {
  return value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
}

/**
 * True when `value` is storable in an attribute bag: a scalar, an array of
 * scalars, or a flat record of scalars.
 *
 * The six adapters used to reach this conclusion with `v as AttributeValue`
 * inside a per-key loop, having checked only that the *bag* was an object. A
 * nested object-of-objects read back from storage was therefore typed as a
 * primitive with nothing enforcing it, and the condition operators compared it
 * as one.
 */
export function iamIsAttributeValue(value: unknown): value is IamPrimitives.AttributeValue {
  if (isScalar(value)) return true
  if (Array.isArray(value)) return value.every(isScalar)
  if (typeof value !== 'object' || value === null) return false
  // Plain objects only. A `Date` (or any class instance) has no own enumerable
  // keys, so `Object.values(...).every(...)` is vacuously true for it and the
  // record arm would wave it through - to be compared later as `{}`.
  const proto = Object.getPrototypeOf(value)
  if (proto !== Object.prototype && proto !== null) return false
  return Object.values(value).every(isScalar)
}

/**
 * Narrows a stored bag to {@link IamPrimitives.Attributes}, or returns `null`
 * when any entry is not a storable attribute value.
 *
 * `null` rather than a bag with the bad keys removed, deliberately. This
 * codebase's settled answer to a corrupt attribute row is to throw, not to
 * report it as empty (`file/index.ts:721`, "Corruption != empty; `{}` would
 * silently strip ABAC"), because an attribute that reads as *absent* retires
 * every deny rule that tests it. Dropping the offending key alone has the same
 * effect for that key, so the whole bag is refused and the caller decides.
 *
 * @param value - The bag as it came out of storage.
 * @returns The narrowed bag, or `null` if `value` is not a flat attribute bag.
 */
export function iamNarrowAttributes(value: unknown): IamPrimitives.Attributes | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  const out: IamPrimitives.Attributes = {}
  for (const [key, entry] of Object.entries(value)) {
    if (!iamIsAttributeValue(entry)) return null
    out[key] = entry
  }
  return out
}
