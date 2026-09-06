---
'@gentleduck/iam': minor
---

Bind the `matches` operator to the operand-type guard it was exempt from.

`evalCondition` throws `IamOperandTypeError` for an operand whose type the
operator cannot compare against, so the condition reads as Indeterminate rather
than as "not met" — `false` is the permissive answer for a deny rule, and
`loadPolicies` does not validate, so a seeded or migrated row reaches the
evaluator exactly as authored. `OPERAND_TYPES` is shared with `validate.libs`
precisely so write-time and read-time cannot drift.

For `matches` they had. The operator was dispatched before the guard ran, so a
non-string or absent `value` fell into `evalMatchesOp`, failed that function's
own `typeof v !== 'string'` test, and answered `false`. A seeded
`deny`-when-`matches` rule therefore never denied, and under
`defaultEffect: 'allow'` the request was allowed outright. The dispatch now sits
below the guard. The refusals `matches` already had — a `$`-sourced pattern, an
uncompilable one — are unchanged.

Also: `IamLRUCache.entries()` used `>` where `get()` uses `>=`, so at an entry's
own expiry millisecond the iterator yielded a value `get()` refuses. The one
caller evicts rather than serves, so nothing was wrong yet; the signature
promises non-expired entries and now keeps that promise.

And `explain()` reported ALLOW on a request naming the reserved refusal token.
`authorize()` and `permissions()` each refuse that token before consulting any
policy - a `'*'` rule matches a sentinel string, so without the refusal the
ordinary wildcard admin grant allows exactly the requests the adapters mint the
token for. `explain()` ran the combine instead and reported what the policies
said, telling an operator investigating a refusal that it was allowed.
`explainEvaluation` now applies the same predicate, keeps the policy traces, and
carries the same `failure: 'input'` tag.
