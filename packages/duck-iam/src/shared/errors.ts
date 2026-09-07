/**
 * The one error type that means "the caller sent something invalid", as opposed
 * to "this package broke".
 *
 * `engine.admin.savePolicy` and `saveRole` validate before they write, and used
 * to signal a rejection with a bare `Error`. Every HTTP integration catches
 * whatever a handler throws and routes it to `onError`, which answers 500 — so
 * a malformed request body, which is the client's mistake, was reported as the
 * server's. The write was correctly refused either way; the status code was the
 * only thing wrong, and a 500 tells a caller to retry something that will never
 * succeed.
 *
 * Extending `Error` rather than replacing it keeps every existing `instanceof
 * Error` check and the exact message text working; the class only adds a way to
 * ask *which kind* of failure this was.
 */
export class IamValidationError extends Error {
  /** Which document failed: a policy or a role. */
  readonly kind: 'policy' | 'role'
  /** The validator's error codes, already formatted with their paths. */
  readonly issues: readonly string[]
  /**
   * The HTTP status this failure deserves.
   *
   * Express, hono and next own their responses and answer 400 themselves. Nest
   * hands errors to its own exception filter, which only maps `HttpException`,
   * and this package does not depend on `@nestjs/common` — so a Nest host reads
   * this field in a filter of its own rather than getting 400 for free.
   */
  readonly status = 400

  constructor(kind: 'policy' | 'role', issues: readonly string[], message: string) {
    super(message)
    this.name = 'IamValidationError'
    this.kind = kind
    this.issues = issues
  }
}

/**
 * True when `value` is a rejection the caller caused.
 *
 * Prefer this over `instanceof` at integration boundaries: a package duplicated
 * in a dependency tree produces two distinct classes, and `instanceof` silently
 * answers `false` for the copy that did not throw. The name check survives that.
 */
export function iamIsValidationError(value: unknown): value is IamValidationError {
  return value instanceof Error && value.name === 'IamValidationError'
}
