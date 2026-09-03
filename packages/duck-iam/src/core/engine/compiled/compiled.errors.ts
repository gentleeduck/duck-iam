/**
 * Compiled-table errors, in their own module so the engine can `instanceof`
 * them without statically importing `compiled.compile.ts`.
 *
 * `compiled.compile` is loaded with a dynamic `import()` so its bake never
 * enters a development bundle. A static import of the error class alone would
 * quietly undo that, and a string match on the message would break the moment
 * someone rewords it - which is the class of silent regression this round has
 * spent its time removing.
 */

/**
 * The role count outran the compiled table's 32-bit grant mask.
 *
 * Distinct from every other compile failure on purpose. A malformed policy is a
 * bug and must keep failing closed - the engine denies and says so. Too many
 * roles is not a bug, it is a capacity limit of one representation, and the
 * interpreter answers the same questions correctly without it. The engine
 * catches *this* error specifically and falls back; anything else still throws.
 *
 * Matching on the message string would have worked until someone reworded it,
 * which is exactly the kind of silent regression this round has been fixing.
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
 * A policy the compiler cannot lower, named.
 *
 * The compiler walks `policy.rules` and each rule's `actions`/`resources`
 * directly. A policy missing one of those throws from wherever the walk happens
 * to touch it first, with a message like `policy.rules is not iterable` and no
 * hint as to which of the tenant's policies is broken. The interpreter, by
 * contrast, isolates a rotten policy and reports its id through
 * `onPolicyError` - so moving both modes onto the table would have traded a
 * precise diagnostic for an anonymous one.
 *
 * This keeps the diagnostic. The shape check runs before the walk, names the
 * policy, and the engine forwards it to `onPolicyError` with that id before
 * rethrowing. The rethrow matters: a malformed policy is a bug, the deny is
 * correct, and only the silence was ever the problem.
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
