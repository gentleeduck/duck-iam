---
'@gentleduck/iam': major
---

Make the HTTP boundary's refusals actually refuse.

**A wildcard rule turned every unmappable request back into an allow.** The
framework adapters map an HTTP request to an `(action, resource)` pair, and some
requests cannot be mapped: an unmapped method, or a path this layer and the
router downstream would read differently. Both were expressed by handing the
engine a sentinel *string* - `IAM_UNKNOWN_ACTION`, `IAM_UNKNOWN_RESOURCE` -
documented as matching no policy and therefore denying. `'*'` matches every
string, sentinels included, so any deployment with a wildcard rule
(`.on('*').of('*')`, the ordinary shape of an admin role) allowed them. The
traversal guard that refuses to resolve `/posts/../admin/secret` handed the
engine `type: 'unknown'`, an admin was allowed, and express, hono, next and nest
then routed the raw target elsewhere - authorized as one resource, served as
another.

A string cannot carry a denial, so the denial moved into the engine: the token
is reserved, and both `authorize()` and `permissions()` refuse it before
consulting any policy. `permissions()` needed it separately because it does not
route through `authorize()`. The refusal reports `failure: 'input'` and fires
`onDeny` like any other denial. Reserving the token means a resource type or
action genuinely named `'unknown'` can no longer be granted; both constants have
always been documented as sentinels that deny.

**A literal backslash was not treated as ambiguous, though `%5C` was.** The
WHATWG URL parser rewrites `\` to `/` in a special-scheme URL before resolving
dot segments, so `new URL('http://x/posts\..\admin').pathname` is `/admin`:
`iamPathIsAmbiguous` read the type as `posts\..\admin` while anything parsing
the target through `URL` read `/admin`. The encoded form was already refused;
the plain character - the easier one to send - was not.

**The default CSRF check allowed cross-site requests on a capital letter.**
`iamDefaultCsrfCheck` read exactly one spelling of `Sec-Fetch-Site` out of a
header Record. Node lowercases what it parses, but the predicate is exported and
documented as taking any request-like object, and not finding the header is
indistinguishable from "no header was sent" - which it treats as a non-browser
caller and allows. The lookup is now case-insensitive across all three supported
header shapes, and reads own properties only.

**A throwing `csrfCheck` escaped the admin gate.** `iamRunAdminAuthz` caught a
throwing `authorize` and reported `phase: 'error'`, but let a throwing
`csrfCheck` propagate, so whether the request was refused depended on the
framework adapter's outer catch. A predicate that cannot answer has not said
yes: it is now `phase: 'forbidden'`, and `authorize` is not called.

**The admin audit could not name who made a mutation.** The gate passed any
truthy `actor` straight into the audit event, and the documented shape -
`authorize: (req) => req.user?.role === 'admin'` - returns a boolean. So the
mutation was authorized and the audit trail recorded `true` as the person who
made it, which attributes it to nobody. A truthy answer still authorizes, as it
always did; a value that names no one is now recorded as no one (`actor:
undefined`), with a one-time notice explaining how to make mutations
attributable. New `iamIsNameableActor` export.

`iamDefaultCsrfCheck`'s five `as` casts were replaced with runtime type
predicates while fixing it.
