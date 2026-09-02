---
'@gentleduck/iam': patch
---

Fix two places where a rule that was correct in development silently stopped applying in production.

**`first-match` / `highest-priority` disagreed between the two evaluation paths on a priority tie.** Both algorithms resolve equal priorities by source order. The interpreter walks `policy.rules` directly and honoured that, but `evaluatePolicyFast` walks the rule index, which buckets literal-resource rules separately from wildcard-resource ones and visits the literal bucket first. A `deny read '*'` declared before an `allow read 'post'` at the same priority therefore denied under `mode: 'development'` and allowed under `mode: 'production'` - the deny disappeared exactly where it mattered most. `Evaluate.IIndexedRule` now carries the rule's index in `policy.rules`, and both tie-break sites in the fast path compare it, so bucket order no longer leaks into the decision. `deny-overrides` and `allow-overrides` were never affected; they are order independent.

The `evaluate == evaluateFast` property oracle covered this shape in principle but drew priorities from 20 values, making ties too rare to hit it. It now draws from 4, so collisions are the common case.

**The condition-nesting limit was off by one between the validator and the evaluator.** `evalConditionGroup` refuses a group at `depth >= MAX_CONDITION_DEPTH` and fails closed, while `validateConditionGroup` only errored at `depth > MAX_CONDITION_DEPTH`. A group nested exactly at the boundary therefore validated cleanly and then never matched. On an allow rule that merely failed closed, but a deny rule at that depth passed validation and silently stopped denying. Both comparisons are now `>=`, so anything the evaluator will refuse is reported as `LIMIT_EXCEEDED` up front.
