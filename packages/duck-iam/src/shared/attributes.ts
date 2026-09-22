import type { IamPrimitives } from '../core/types'

/**
 * Adapter-boundary guard for `setSubjectAttributes`: refuses a non-object (a string would spread into per-character
 * keys) and a `__proto__` key, with the same message on every adapter.
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
  if (hasForbiddenAttributeKey(attrs)) {
    throw new Error(
      `[@gentleduck/iam:${adapter}] attributes for "${subjectId}" must not contain a ${FORBIDDEN_ATTRIBUTE_KEY} key`,
    )
  }
}

/**
 * The one attribute name that cannot round-trip: assigning `__proto__` sets the prototype, while `JSON.parse` makes it
 * an own key.
 */
const FORBIDDEN_ATTRIBUTE_KEY = '__proto__'

/** Does this bag carry the one key that cannot survive a round trip intact? */
function hasForbiddenAttributeKey(value: object): boolean {
  return Object.hasOwn(value, FORBIDDEN_ATTRIBUTE_KEY)
}

/** True for a JSON scalar: `string | number | boolean | null`. */
function isScalar(value: unknown): value is IamPrimitives.Scalar {
  return value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
}

/** True when `value` is storable in an attribute bag: a scalar, an array of scalars, or a flat record of scalars. */
export function iamIsAttributeValue(value: unknown): value is IamPrimitives.AttributeValue {
  if (isScalar(value)) return true
  if (Array.isArray(value)) return value.every(isScalar)
  if (typeof value !== 'object' || value === null) return false
  // NOTE: plain objects only. A `Date` has no own enumerable keys, so the record check below would pass it vacuously.
  const proto = Object.getPrototypeOf(value)
  if (proto !== Object.prototype && proto !== null) return false
  return Object.values(value).every(isScalar)
}

/**
 * Narrows a stored bag to {@link IamPrimitives.Attributes}, or returns `null` when any entry is not storable.
 * SECURITY: refuses the whole bag, not just bad keys; an absent attribute retires every deny rule testing it.
 *
 * @param value - The bag as it came out of storage.
 * @returns The narrowed bag, or `null` if `value` is not a flat attribute bag.
 */
export function iamNarrowAttributes(value: unknown): IamPrimitives.Attributes | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  // SECURITY: a `__proto__` key cannot be stored as itself, so refuse the bag rather than read its contents as absent.
  if (hasForbiddenAttributeKey(value)) return null
  const out: IamPrimitives.Attributes = {}
  for (const [key, entry] of Object.entries(value)) {
    if (!iamIsAttributeValue(entry)) return null
    // SECURITY: not `out[key] = entry`, which for `__proto__` runs the inherited setter and makes the value the bag's
    // prototype; `defineProperty` always stores an own data property.
    Object.defineProperty(out, key, { configurable: true, enumerable: true, value: entry, writable: true })
  }
  return out
}

/**
 * A caller-owned copy of an attribute bag, one level deep: as deep as {@link IamPrimitives.AttributeValue} goes.
 * WARN: a plain spread aliases nested arrays and records; in-memory adapters copy on both read and write.
 *
 * @returns A copy that shares no mutable object with `attrs`.
 */
export function iamCopyAttributes(attrs: IamPrimitives.Attributes): IamPrimitives.Attributes {
  const out: IamPrimitives.Attributes = {}
  for (const [key, value] of Object.entries(attrs)) {
    if (Array.isArray(value)) out[key] = [...value]
    else if (value !== null && typeof value === 'object') out[key] = { ...value }
    else out[key] = value
  }
  return out
}
