---
'@gentleduck/iam': minor
---

Authorization-correctness audit: behaviour fixes and the documentation defects
that were hiding them.

### The permission map allowed what `can()` denied

`permissions()` evaluated every check against a resource with no attributes,
while keying the answer by `resourceId`. A caller reads that key as an answer
about that instance, but a rule conditioned on `resource.attributes.*` could not
fire, so a deny written that way was invisible: `read:post:42` came back `true`
for the very row `can()` refuses.

`IamClient.IPermissionCheck` now takes an optional `attributes`, and each check
is evaluated against the attributes it carries. A check that omits them is
unchanged, and still answers about an instance that has none — now stated in the
reference instead of being inferred from the key.

The route guards (`iamAccessMiddleware`, `iamGuard`, `iamNestAccessGuard`,
`createIamNextMiddleware`, `checkIamAccess`, `createIamSubjectCan`) share the
blind spot for a structural reason: they run before the handler has loaded the
row, so there are no attributes to pass. That is now documented on each of them
and in the server reference, with the guidance the omission was hiding — the
guard is the coarse gate on type, id and scope, and an attribute-dependent rule
has to be re-checked with `can()` once the row is in hand.
