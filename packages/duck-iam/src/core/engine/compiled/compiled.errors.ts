// Compiled-table errors, in their own module so the engine can `instanceof` them without a static import of
// `compiled.compile`, which is loaded with dynamic `import()` to keep it out of development bundles.

/**
 * The role count exceeds the compiled table's 32-bit grant mask.
 * NOTE: a capacity limit, not a bug: the engine catches this class and falls back to the interpreter.
 */
export class IamRoleLimitExceededError extends Error {
  readonly name = 'IamRoleLimitExceededError'
  readonly tag = 'duck-iam/role-limit-exceeded'
  readonly roleCount: number
  readonly limit: number
  constructor(roleCount: number, limit: number) {
    super(
      `[@gentleduck/iam:compiled] compileTable(): ${roleCount} roles exceeds the ${limit}-role limit the compiled table's 32-bit grant mask can address without bit-index aliasing (role N and role N+32 would silently share a bit). The engine falls back to the interpreter, which has no such limit; expect lower throughput until the role count comes down.`,
    )
    this.roleCount = roleCount
    this.limit = limit
  }
}

/**
 * A policy the compiler cannot lower, named so the engine can report its id to `onPolicyError`.
 * SECURITY: the engine rethrows after reporting, so a malformed policy still fails closed.
 */
export class IamPolicyCompileError extends Error {
  readonly name = 'IamPolicyCompileError'
  readonly tag = 'duck-iam/policy-compile-failed'
  readonly policyId: string
  constructor(policyId: string, detail: string) {
    super(
      `[@gentleduck/iam:compiled] compileTable(): policy ${JSON.stringify(policyId)} cannot be compiled: ${detail}.`,
    )
    this.policyId = policyId
  }
}
