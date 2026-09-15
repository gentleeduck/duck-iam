/**
 * Results and issue shapes produced by the validators. Type-only.
 * Validators report instead of throwing, so a caller such as an admin UI sees every problem at once.
 */
export namespace IamValidate {
  /**
   * Closed set of machine-readable codes the validator can emit. Switch on this
   * to drive UI / telemetry; the compiler enforces exhaustiveness.
   */
  export type ValidationCode =
    | 'BROAD_ALLOW'
    | 'CIRCULAR_INHERIT'
    | 'DANGLING_INHERIT'
    | 'DUPLICATE_ROLE_ID'
    | 'DUPLICATE_RULE_ID'
    | 'EMPTY_ROLE'
    | 'ERR_REGEX_CATASTROPHIC'
    | 'ERR_REGEX_INVALID'
    | 'ERR_REGEX_USER_SOURCED'
    | 'INHERITANCE_TOO_DEEP'
    | 'INVALID_ALGORITHM'
    | 'INVALID_CONDITION'
    | 'INVALID_EFFECT'
    | 'INVALID_OPERATOR'
    | 'INVALID_RULE'
    | 'INVALID_TYPE'
    | 'LIMIT_EXCEEDED'
    | 'MISSING_FIELD'
    | 'MISSING_VALUE'
    | 'OPERAND_TYPE_MISMATCH'
    | 'UNREACHABLE_TARGET'
    | 'UNKNOWN_FIELD'
    | 'UNRESOLVABLE_FIELD'
    | 'UNRESOLVABLE_VALUE'

  /** A single validation issue; errors flip {@link IResult.valid} to `false`, warnings do not. */
  export interface IIssue {
    /** `'error'` blocks usage, `'warning'` is informational. */
    readonly type: 'error' | 'warning'
    /** Machine-readable code - see {@link ValidationCode}. */
    readonly code: ValidationCode
    /** Human-readable description. */
    readonly message: string
    /** Role ID involved, when emitted by role validation. */
    readonly roleId?: string
    /** Dot-path into the offending field, when emitted by policy validation. */
    readonly path?: string
  }

  /**
   * The action / resource / scope vocabulary `validateRoles` checks grants against.
   * An omitted or empty list leaves that axis unconstrained; it does not forbid everything.
   */
  export interface IDeclaredSurface {
    /** Declared actions. `'*'` in a grant is always allowed. */
    readonly actions?: readonly string[]
    /** Declared resources. `'*'` in a grant is always allowed. */
    readonly resources?: readonly string[]
    /** Declared scopes. `'*'` and an omitted scope are always allowed. */
    readonly scopes?: readonly string[]
  }

  /** The result of a validation; `valid` is `true` when there are no error-level issues. */
  export interface IResult {
    /** Whether the validated input is free of errors. */
    readonly valid: boolean
    /** All issues found during validation (both errors and warnings). */
    readonly issues: readonly IIssue[]
  }
}
