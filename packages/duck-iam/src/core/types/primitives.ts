/**
 * Leaf value types: what an attribute may be, and the bags they come in. Type-only.
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
