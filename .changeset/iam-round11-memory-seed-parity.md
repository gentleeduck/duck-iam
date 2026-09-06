---
'@gentleduck/iam': minor
---

Make `IamMemoryAdapter`'s constructor agree with its own write methods.

A seeded assignment naming a role the init does not declare is now refused, with
the same message `assignRole` throws. It was accepted, `getSubjectRoles`
returned the id, and a hand-written ABAC rule keyed on `subject.roles` fired on
it — an allow from a role that does not exist. `resolveEffectiveRoles` drops a
dangling `inherits` id, but a directly assigned role is not that case.

`getSubjectAttributes` returns a copy rather than the live internal bag, and the
attributes seed copies in. Editing what a read handed back used to rewrite the
store, with no validation and nothing to invalidate a cache from. The other five
adapters already rebuild the bag through `iamNarrowAttributes`.

This adapter is documented "tests + prototypes only", so neither is a production
grant path. Seeds that declare the roles they assign are unaffected.

Report the adapter-compliance suite's optional-method skips honestly. Nineteen
tests in `runAdapterCompliance` bowed out with a bare `return` when the adapter
under test does not implement an optional method, reporting as passed; across
the tier that was 59 green ticks asserting nothing. They now report as skipped,
and a new support matrix asserts which adapters implement which optional
methods, so dropping one turns a test red instead of turning five silent.
