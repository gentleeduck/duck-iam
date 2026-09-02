import type { AccessControl } from '../types'

export namespace Evaluate {
  /**
   * Signature of a combining-algorithm implementation. Takes an array of
   * matched rules (paired with their effect) plus a default effect, and
   * returns the winning rule (if any), the final effect, and a reason string.
   */
  export type Combiner = (
    matched: Array<{ rule: AccessControl.IRule; effect: AccessControl.Effect }>,
    defaultEffect: AccessControl.Effect,
  ) => { rule?: AccessControl.IRule; effect: AccessControl.Effect; reason: string }

  /**
   * Rule + its `action` / `resource` pattern sets, as held inside a
   * {@link IPolicyRuleIndex}.
   */
  export interface IIndexedRule {
    readonly rule: AccessControl.IRule
    readonly actions: Set<string>
    readonly resources: Set<string>
    readonly hasWildcardAction: boolean
    readonly hasWildcardResource: boolean
    /** Pre-computed `('all' in cond || 'any' in cond || 'none' in cond)`. Avoids three `in` checks per hot-path entry. */
    readonly hasConditions: boolean
    /**
     * Position of this rule in `policy.rules`. `first-match` / `highest-priority`
     * resolve equal priorities by source order, but the fast path visits literal
     * buckets before wildcard ones, so bucket order is not source order. Carrying
     * the index lets the tie-break stay faithful to the interpreter.
     */
    readonly order: number
  }

  /**
   * Pre-computed index over a policy's rules. Lookup is O(1) on the exact key;
   * a rule with an expansive (`*` / `foo:*` / `foo.*`) action or resource is
   * bucketed by whichever side of it is still literal, so a request only
   * scans the (usually small) set of rules whose literal side already
   * matches - not every expansive rule in the policy. Built once per policy
   * reference and cached in a {@link WeakMap}.
   */
  export interface IPolicyRuleIndex {
    /** Literal `action\0resource` keys; covers rules with no expansive patterns. */
    readonly byActionResource: Map<string, IIndexedRule[]>
    /** Literal action -> rules whose resource is expansive; resource still needs a match check. */
    readonly byActionWildcardResource: Map<string, IIndexedRule[]>
    /** Literal resource -> rules whose action is expansive; action still needs a match check. */
    readonly byResourceWildcardAction: Map<string, IIndexedRule[]>
    /** Rules with an expansive action AND an expansive resource - neither side is indexable; matched by scan. */
    readonly wildcardBoth: IIndexedRule[]
    /**
     * `action -> resource -> effect` for unconditional rules in a wildcardless
     * policy. Lets the fast path return without scanning. Empty otherwise.
     */
    readonly precomputed: Map<string, Map<string, boolean>>
  }
}
