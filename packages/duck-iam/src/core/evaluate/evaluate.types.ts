import type { AccessControl } from '../types'

/**
 * Evaluator internals, type-only: the combining-algorithm signature and the per-policy rule index the fast path uses.
 * Rules are bucketed by whichever of `action` / `resource` is literal, so a request scans few wildcard rules.
 */
export namespace Evaluate {
  /** A combining-algorithm implementation: matched rules and a default effect in, winning rule/effect/reason out. */
  export type Combiner = (
    matched: Array<{ rule: AccessControl.IRule; effect: AccessControl.Effect }>,
    defaultEffect: AccessControl.Effect,
  ) => { rule?: AccessControl.IRule; effect: AccessControl.Effect; reason: string }

  /** A rule plus its `action` / `resource` pattern sets, as held inside a {@link IPolicyRuleIndex}. */
  export interface IIndexedRule {
    readonly rule: AccessControl.IRule
    readonly actions: Set<string>
    readonly resources: Set<string>
    /** Pre-computed `!matchesUnconditionally(rule.conditions)`. PERF: decided once per index, not per request. */
    readonly hasConditions: boolean
    /**
     * Position of this rule in `policy.rules`. The fast path visits literal buckets first, so bucket order is not
     * source order; `first-match` / `highest-priority` break ties on this to stay faithful to the interpreter.
     */
    readonly order: number
  }

  /**
   * Pre-computed index over a policy's rules: O(1) on an exact key, and an expansive (`*`, `foo:*`, `foo.*`) side
   * is bucketed by whichever side is still literal. Built once per `rules` array and cached in a {@link WeakMap}.
   */
  export interface IPolicyRuleIndex {
    /**
     * Two-level literal action -> literal resource -> rules; covers rules with no expansive pattern.
     * SECURITY: not a single `` `${action}\0${resource}` `` key, which is not injective. See `addToPairBucket`.
     */
    readonly byActionResource: Map<string, Map<string, IIndexedRule[]>>
    /** Literal action -> rules whose resource is expansive; resource still needs a match check. */
    readonly byActionWildcardResource: Map<string, IIndexedRule[]>
    /** Literal resource -> rules whose action is expansive; action still needs a match check. */
    readonly byResourceWildcardAction: Map<string, IIndexedRule[]>
    /** Rules with an expansive action AND an expansive resource - neither side is indexable; matched by scan. */
    readonly wildcardBoth: IIndexedRule[]
    /** `action -> resource -> allowed` for unconditional rules in a wildcardless policy; empty otherwise. */
    readonly precomputed: Map<string, Map<string, boolean>>
    /**
     * Some rule carries a condition that can throw; `conditionMayThrow` decides which shapes count.
     * SECURITY: such a policy is Indeterminate as a whole, so the fast path hands it to the interpreter rather
     * than reaching a verdict before the throwing rule runs.
     */
    readonly mayThrow: boolean
  }
}
