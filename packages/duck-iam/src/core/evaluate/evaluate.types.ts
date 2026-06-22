import type { IamAccessControl } from '../types'

export namespace IamEvaluate {
  /**
   * Signature of a combining-algorithm implementation. Takes an array of
   * matched rules (paired with their effect) plus a default effect, and
   * returns the winning rule (if any), the final effect, and a reason string.
   */
  export type Combiner = (
    matched: Array<{ rule: IamAccessControl.IRule; effect: IamAccessControl.Effect }>,
    defaultEffect: IamAccessControl.Effect,
  ) => { rule?: IamAccessControl.IRule; effect: IamAccessControl.Effect; reason: string }

  /**
   * Rule + its `action` / `resource` pattern sets, as held inside a
   * {@link IPolicyRuleIndex}.
   */
  export interface IIndexedRule {
    readonly rule: IamAccessControl.IRule
    readonly actions: Set<string>
    readonly resources: Set<string>
    readonly hasWildcardAction: boolean
    readonly hasWildcardResource: boolean
    /** Pre-computed `('all' in cond || 'any' in cond || 'none' in cond)`. Avoids three `in` checks per hot-path entry. */
    readonly hasConditions: boolean
  }

  /**
   * Pre-computed index over a policy's rules. Lookup is O(1) on the exact key,
   * O(wildcardAny) on the expansive fallback. Built once per policy reference
   * and cached in a {@link WeakMap}.
   */
  export interface IPolicyRuleIndex {
    /** Literal `action\0resource` keys; covers rules with no expansive patterns. */
    readonly byActionResource: Map<string, IIndexedRule[]>
    /** Rules with `*` / `foo:*` / `foo.*` in actions or resources; matched by scan. */
    readonly wildcardAny: IIndexedRule[]
    /**
     * `action -> resource -> effect` for unconditional rules in a wildcardless
     * policy. Lets the fast path return without scanning. Empty otherwise.
     */
    readonly precomputed: Map<string, Map<string, boolean>>
  }
}
