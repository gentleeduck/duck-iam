/**
 * The one error type that means "the caller sent something invalid", as opposed to "this package broke".
 * Carries status 400 so integrations do not answer a caller's mistake with 500; `instanceof Error` still holds.
 */
export class IamValidationError extends Error {
  /** What failed: a policy document, a role document, or a field of the request itself. */
  readonly kind: 'policy' | 'role' | 'request'
  /** The validator's error codes, already formatted with their paths. */
  readonly issues: readonly string[]
  /** The HTTP status this failure deserves. */
  readonly status = 400

  /**
   * The same status under the name Nest reads.
   * INFO: Nest's base exception filter answers 500 for a non-`HttpException` unless it has `statusCode` and `message`.
   */
  readonly statusCode = 400

  constructor(kind: 'policy' | 'role' | 'request', issues: readonly string[], message: string) {
    super(message)
    this.name = 'IamValidationError'
    this.kind = kind
    this.issues = issues
  }
}

/**
 * True when `value` is a rejection the caller caused.
 * NOTE: matches on `name`, since `instanceof` fails when the package is duplicated in the dependency tree.
 */
export function iamIsValidationError(value: unknown): value is IamValidationError {
  return value instanceof Error && value.name === 'IamValidationError'
}
