import type { AccessControl, IamPrimitives } from '../types'
/**
 * The decision trace: every policy and rule that was consulted, what each one
 * voted, and which one decided. Type-only.
 *
 * Produced by `engine.explain()` rather than by `can()` - a check answers a
 * boolean on the fast path, and reconstructing why is deliberately a separate,
 * slower call so debugging never taxes production authorization.
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
     * Plain-text human-readable summary. INFO-B: contains policy IDs, subject
     * IDs, role IDs verbatim - values may be operator-controlled (admin-supplied
     * policy names) or attacker-influenced (subject IDs from request paths).
     * Downstream consumers that render this into HTML must HTML-escape it
     * themselves; the explain pipeline never escapes for any specific
     * rendering target.
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
   *   // Plain role IDs, never a `scope:role` composite. The engine derives
   *   // this as `enrichedSubject.roles` minus `originalRoles`, so it names the
   *   // roles a scoped grant *added* - which scope added them is not encoded
   *   // here. This example used to show a scope-qualified composite, which is
   *   // a shape nothing in the package emits.
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
