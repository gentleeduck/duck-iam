export namespace IamPrimitives {
  /**
   * Single scalar value: every JSON-compatible primitive the condition engine
   * can compare. Leaf of the duck-iam type system.
   */
  export type Scalar = string | number | boolean | null

  /**
   * Any value storable in an attribute map or usable as a condition operand  -
   * a single {@link Scalar} or an array of scalars. Arrays drive set operators
   * (`in`, `nin`, `subset_of`, `superset_of`).
   */
  export type AttributeValue = Scalar | Scalar[] | Record<string, Scalar>

  /**
   * String-keyed record of {@link AttributeValue} entries. Used for subject
   * attributes, resource attributes, environment, and metadata bags.
   */
  export type Attributes = Record<string, AttributeValue>
}
