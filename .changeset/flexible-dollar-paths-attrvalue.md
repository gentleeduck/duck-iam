---
'@gentleduck/iam': minor
---

Add FlexibleDollarPaths for $-value autocomplete and fix AttrValue for optional properties

- FlexibleDollarPaths<TContext> added directly to method value signatures so the IDE shows $-prefixed autocomplete (e.g. $subject.id) even without a custom context
- AttrValue now strips undefined from optional properties — yearsExperience?: number correctly resolves to number instead of falling back to AttributeValue
- StringConditionValue no longer includes (string & {}) internally — the flexible string fallback is handled at the method signature level via FlexibleDollarPaths
