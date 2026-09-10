import type { AccessControl, IamPrimitives } from '../types'
/**
 * The decision trace: every policy and rule consulted, what each voted, and which one decided. Type-only.
 * PERF: produced by `engine.explain()`, never by `can()`, so reconstructing the reasoning never taxes the fast path.
 */
export namespace Explain {
  /**
   * Trace of a single leaf condition: field, operator, expected vs actual, and the result.
   *
   * @example
   * ```ts
   * const leaf: Explain.ILeafTrace = {
   *   type: 'condition',
   *   field: 'subject.attributes.tier',
   *   operator: 'eq',
   *   expected: 'gold',
   *   actual: 'silver',
   *   result: false,
   * }
   * ```
   */
  export interface ILeafTrace {
    readonly type: 'condition'
    readonly field: string
    readonly operator: AccessControl.Operator
    /** The right-hand side value the condition expected. */
    readonly expected: IamPrimitives.AttributeValue
    /** The left-hand side value resolved from the request. */
    readonly actual: IamPrimitives.AttributeValue
    readonly result: boolean
  }

  /**
   * Trace of a condition group (`all` / `any` / `none`): child traces + the group result.
   *
   * @example
   * ```ts
   * const group: Explain.IGroupTrace = {
   *   type: 'group',
   *   logic: 'all',
   *   result: false,
   *   children: [leafA, leafB],
   * }
   * ```
   */
  export interface IGroupTrace {
    readonly type: 'group'
    readonly logic: 'all' | 'any' | 'none'
    readonly result: boolean
    readonly children: ReadonlyArray<ILeafTrace | IGroupTrace>
  }

  /**
   * Union of leaf and group traces - the recursive element type in explain output.
   *
   * @example
   * ```ts
   * function walk(trace: Explain.Trace): void {
   *   if (trace.type === 'condition') console.log(trace.field, trace.result)
   *   else trace.children.forEach(walk)
   * }
   * ```
   */
  export type Trace = ILeafTrace | IGroupTrace

  /**
   * Trace of a single rule: action / resource / condition match status, plus the conditions tree.
   *
   * @example
   * ```ts
   * const rule: Explain.IRuleTrace = {
   *   ruleId: 'admin-can-write',
   *   effect: 'allow',
   *   priority: 100,
   *   actionMatch: true,
   *   resourceMatch: true,
   *   conditionsMet: true,
   *   conditions: group,
   *   matched: true,
   * }
   * ```
   */
  export interface IRuleTrace {
    readonly ruleId: string
    readonly description?: string
    readonly effect: AccessControl.Effect
    readonly priority: number
    readonly actionMatch: boolean
    readonly resourceMatch: boolean
    readonly conditionsMet: boolean
    readonly conditions: IGroupTrace
    readonly matched: boolean
    /**
     * Set when tracing this rule's conditions threw; absent on every rule that evaluated normally.
     * NOTE: that is Indeterminate, not a non-match, so the rule reads `matched: false` while the policy result votes.
     */
    readonly conditionError?: string
  }

  /**
   * Trace of a single policy evaluation: targets, rule traces, combiner result.
   *
   * @example
   * ```ts
   * const policy: Explain.IPolicyTrace = {
   *   policyId: 'docs-acl',
   *   policyName: 'Documents ACL',
   *   algorithm: 'deny-overrides',
   *   targetMatch: true,
   *   rules: [ruleTrace],
   *   result: 'allow',
   *   reason: 'admin-can-write matched',
   * }
   * ```
   */
  export interface IPolicyTrace {
    readonly policyId: string
    readonly policyName: string
    readonly algorithm: AccessControl.CombiningAlgorithm
    readonly targetMatch: boolean
    readonly rules: readonly IRuleTrace[]
    readonly result: AccessControl.Effect
    readonly reason: string
    readonly decidingRuleId?: string
    readonly decidingRule?: AccessControl.IRule
  }

  /**
   * Complete trace returned by `engine.explain()`.
   *
   * @example
   * ```ts
   * // `attributes` is required on IResource - pass `{}` when the resource has none.
   * const trace: Explain.IResult = await engine.explain('user-1', 'read', {
   *   type: 'post',
   *   attributes: {},
   * })
   * trace.policies.forEach((p) => console.log(p.policyId, p.result, p.reason))
   * ```
   */
  export interface IResult {
    readonly decision: AccessControl.IDecision
    readonly request: {
      readonly action: string
      readonly resourceType: string
      readonly resourceId?: string
      readonly scope?: string
    }
    readonly subject: {
      readonly id: string
      readonly roles: readonly string[]
      readonly scopedRolesApplied: readonly string[]
      readonly attributes: Readonly<Record<string, IamPrimitives.AttributeValue>>
    }
    readonly policies: readonly IPolicyTrace[]
    /**
     * Plain-text human-readable summary.
     * SECURITY: carries policy, subject and role ids verbatim, some attacker-influenced. The pipeline never escapes
     * for a rendering target, so a consumer rendering this into HTML must escape it (see `iamEscapeHtml`).
     */
    readonly summary: string
  }

  /**
   * Subject metadata passed to {@link explainEvaluation} for building the explain trace.
   *
   * @example
   * ```ts
   * const info: Explain.ISubjectInfo = {
   *   subjectId: 'user-1',
   *   originalRoles: ['editor'],
   *   // Plain role ids, never a scope-qualified composite: these are the roles a scoped grant added, and which
   *   // scope added them is not encoded here.
   *   scopedRolesApplied: ['admin'],
   * }
   * ```
   */
  export interface ISubjectInfo {
    subjectId: string
    originalRoles: readonly string[]
    scopedRolesApplied: readonly string[]
  }
}
