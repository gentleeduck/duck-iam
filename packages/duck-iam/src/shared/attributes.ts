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
  if (hasForbiddenAttributeKey(attrs)) {
    throw new Error(
      `[@gentleduck/iam:${adapter}] attributes for "${subjectId}" must not contain a ${FORBIDDEN_ATTRIBUTE_KEY} key`,
    )
  }
}

/**
 * The one attribute name that cannot be stored and read back as itself.
 *
 * `__proto__` is an accessor on `Object.prototype`, so a plain assignment of it
 * sets the target's prototype instead of adding a key. `JSON.parse` makes it an
 * own property, which is how one reaches storage in the first place - an admin
 * request body is parsed, spread into a bag, and written.
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
  // Refused outright, not carried across as an own key. `iamIsAttributeValue`
  // is happy with the value - a flat record of scalars is legitimate - so the
  // bag would read back with a `__proto__` key and nothing else, and every
  // attribute the operator meant to store under it would be *absent*. Absent
  // is the dangerous answer: it retires every deny rule that tests the
  // attribute, which is the same reason a corrupt bag throws instead of
  // reading as `{}`. Refusing hands the caller the row to repair.
  if (hasForbiddenAttributeKey(value)) return null
  const out: IamPrimitives.Attributes = {}
  for (const [key, entry] of Object.entries(value)) {
    if (!iamIsAttributeValue(entry)) return null
    // `out[key] = entry` runs the inherited `__proto__` SETTER for that one key
    // name, and two things go wrong at once. The key the operator stored is not
    // in the bag, so a deny rule testing it reads `undefined` and retires; and
    // the value becomes the bag's prototype, so every key inside it answers by
    // inheritance - a stored `{"__proto__":{"tier":"gold"}}` makes
    // `attributes.tier` read `'gold'` for a subject nobody granted it. Both
    // halves are reachable from any row a hand-written script or an older
    // version wrote, and `iamIsAttributeValue` waves the value through because
    // a flat record of scalars is a legitimate attribute value.
    //
    // `defineProperty` stores it as the own data property it was written as.
    Object.defineProperty(out, key, { configurable: true, enumerable: true, value: entry, writable: true })
  }
  return out
}
