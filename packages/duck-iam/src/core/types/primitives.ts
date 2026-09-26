/**
 * Leaf value types: what an attribute may be, and the bags they come in, plus the runtime predicates that narrow
 * to them - the one place either is defined, so every caller narrows the same way.
 * NOTE: kept narrow to what every adapter can compare, serialize and store.
 */
export namespace IamPrimitives {
  /** A JSON primitive the condition engine can compare. */
  export type Scalar = string | number | boolean | null

  /**
   * An attribute or condition operand: a {@link Scalar}, an array of scalars, or a flat record of scalars.
   * Arrays drive the set operators (`in`, `nin`, `subset_of`, `superset_of`).
   */
  export type AttributeValue = Scalar | Scalar[] | Record<string, Scalar>

  /**
   * String-keyed {@link AttributeValue} bag for subject and resource attributes, environment and metadata.
   */
  export type Attributes = Record<string, AttributeValue>
}

/** Whether `value` is a {@link IamPrimitives.Scalar}; takes `unknown`, for use before anything is narrowed. */
export function iamIsScalar(value: unknown): value is IamPrimitives.Scalar {
  return value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
}

/** Whether `value` is storable as an {@link IamPrimitives.AttributeValue}: a scalar, an array of scalars, or a flat record of scalars. */
export function iamIsAttributeValue(value: unknown): value is IamPrimitives.AttributeValue {
  if (iamIsScalar(value)) return true
  if (Array.isArray(value)) return value.every(iamIsScalar)
  if (typeof value !== 'object') return false
  // NOTE: plain objects only. A `Date` has no own enumerable keys, so the record check below would pass it vacuously.
  const proto = Object.getPrototypeOf(value)
  if (proto !== Object.prototype && proto !== null) return false
  return Object.values(value).every(iamIsScalar)
}
