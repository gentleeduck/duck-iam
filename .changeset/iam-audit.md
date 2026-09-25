---
'@gentleduck/iam': minor
---

Security and correctness fixes from the ongoing audit, grouped by what goes wrong
if you do not take them.

**A request could reach a protected route with no decision made.**
`createIamNextMiddleware` tested each rule against the caller's own `RegExp`
object. A pattern carrying `/g` or `/y` advances `lastIndex` and keeps it on the
shared rule, so every second request matched no rule at all — and a middleware
that matches no rule returns `null`, which the documented caller turns into
`NextResponse.next()`. Where a broader rule followed, the request was authorised
under the wrong one instead. The stateful flags are now stripped once, when the
middleware is built.

**A read-only subject could delete.** In Nest, `@IamAuthorize({ resource })` with
no `action` and no `infer` resolved to the literal `'read'` on every HTTP method,
so a DELETE route was guarded by a read check: the viewer got through and the
editor who actually held `delete` was refused. The action now falls back to the
request method, as `createIamNextMiddleware` already did. On a GET route the
derived action is still `read`, so this can only turn wrong allows into denies.

**Your denies could go missing while your grants survived.** Over HTTP, a list
endpoint answering with anything but a bare array — an envelope such as
`{"policies": [...]}`, a proxy's `{"status":"ok"}`, a JSON `null`, an empty body
— was read as an empty list. That is not fail-closed: `loadAllPolicies` merges
the RBAC policy built from `/roles`, a separate read, so every role grant stayed
and only the explicit denies vanished. A single unreadable *row* already refused
for exactly this reason; losing the whole list now refuses too. Note that
`engine.healthCheck()` probes `listPolicies`, so an affected node had also been
reporting healthy on an empty policy model. A `baseUrl` ending in a bare `?` or
`#` — what a URL builder emits for empty search params — also slipped past its
own validation and sent every request into the query string, which is one way to
reach that empty body.

**A grant you issued could silently not exist.** In the drizzle adapter an
assignment's identity is `(subject, role, scope)` and does not include its
window, so re-granting a role whose window had elapsed hit the unique index and
did nothing — no error, no role, and an audit log that recorded `role.assigned`
regardless. An elapsed row is no longer treated as a duplicate. The same applied
to `assignRoleMany`, and to `updateAssignmentScope`, which on a move onto an
elapsed target deleted the *live* source row and returned `true`. A live
duplicate is still a no-op, so idempotence is unchanged.

**A corrupt role row could turn a deny into an allow.** Every adapter refused a
malformed *policy* row but skipped a malformed *role* row, on the grounds that a
role's permissions only grant. They do — but the role **id** is what a deny
selects on, through `targets.roles` and through `subject.roles contains "x"` in a
rule condition. Skipping the definition drops the id out of the subject's
effective roles (the `inherits` edge that reached it becomes dangling and is
pruned), so those denies stop applying while the grants from the subject's other
roles stand. A subject holding `super` (which inherits `admin`) and `staff` went
from denied to allowed on `delete post` purely because the `admin` row failed to
parse. The `targets.roles` spelling was at least reported by
`reportUnreachableRoleTargets`; the condition spelling produced no warning at all
beyond the row-level parse error. Malformed role rows are now refused like policy
rows, in all five adapters.

**A grant you issued could be impossible to revoke.** The HTTP adapter validated
role ids that travel in the URL path but not the one `assignRole` sends in the
body, so a server-owned id containing `/` assigned cleanly and then failed every
`revokeRole` with "role id cannot contain a path separator". Nothing in
`validateRole` forbids that id, and the shared helper already documents that
"reads and writes share it, so a write cannot store an id no read can fetch" —
`assignRole` was the one call site that skipped it.

**Stored data could be read as absent.** The redis adapter tested read values for
truthiness, so an empty string — a stored blob, not a missing key — bypassed the
corrupt-row guards. Subject attributes came back as `{}`, dropping every
attribute from the decision, and `getPolicy`/`getRole` reported "no such row"
where `listPolicies` threw on the same bytes. These now test for `null`.

**A revocation could be cached over.** `admin.setAttributes` was the only admin
write that did not go through `writeThenInvalidate`, so a call that rejected or
timed out but still landed left the old attributes cached for a full `cacheTTL`
— and subject attributes feed ABAC conditions, so a downgrade that landed kept
allowing. `admin.import()` had the same gap in a different shape: it invalidated
only on the success path, so a failure partway through left the rows that did
land absent from every cache, and in `replace` mode the deletes had already run,
so store and cache disagreed in both directions. Both now invalidate whatever the
outcome.

**A signing secret nobody set could look configured.** The redis invalidator
accepted `secret: ''` as a key. `createHmac('sha256', '')` is legal, so with the
documented `secret: process.env.IAM_INVALIDATE_SECRET` wiring, an environment
variable that exists but is empty ran the channel "signed" with a key anyone can
forge — and the "accepting unsigned pub/sub" warning stayed silent, because a
secret was present. Peers holding a real key dropped this node's publishes, so
fleet invalidation died one-way with both ends looking configured. An empty
secret is now refused at construction.

**A re-subscribe could leave the fleet silently deaf.** Tearing the redis
invalidator down while a subscribe was still in flight cleared `subscribed` but
left `subscribing` set, so the next `subscribe()` returned early and never
re-registered with the client — after which the in-flight promise set
`subscribed` back to `true`. The node then reported a subscription it did not
have, `publish`'s opportunistic retry short-circuited on the same flag, and
`healthCheck` omits the invalidator field when status says subscribed, so it kept
serving stale allows after a fleet-wide revoke with no path back. This is not a
race — a fully synchronous client hits it too — and it is reachable from
`dispose()` plus re-construct, or from `setInvalidator` re-attaching one
instance.

**A permissions endpoint could crash your UI.** React and Vue `usePermissions`
stored the fetch body as-is; a JSON `null` reached `iamPermissionGranted` and
threw out of render. Both now keep a frozen copy, matching `IamAccessClient`,
`fromServer`, React's `AccessProvider` and Vue's `createAccessState`.

**Smaller fixes.** A `baseUrl` of the form `http://[::127.0.0.1]` arrives from
Node as `[::7f00:1]` and was the one spelling of loopback the SSRF guard let
through; it now unwraps the hex tail like the mapped, 6to4 and NAT64 forms beside
it. A deny policy whose `actions` end in `.*` never matches at request time and
was also never reported as dead, because the dead-target reporter read `.*` as a
prefix on both axes while `matchesAction` honours `:*` only; the reporter now
agrees with the matcher. An engine that hit the role limit could latch itself
onto the interpreter permanently using a role count the store had already
retired, and now carries the same generation guard as the compiled table beside
it. And the role-cache invalidation path no longer moves the hit/miss counters
that feed `cacheHitRate`, so a replica applying broadcasts does not drift its own
reported rate.

Also removed two dead branches: an unreachable empty-scope check in the file
adapter that duplicated the shared guard called two lines above it, and two arms
of `IamAdminAudit.Target` that nothing emits.

**The error surface changed shape.** Every `IamXxxError` class this package used
to throw — `IamRegexInputTooLargeError`, `IamConditionGroupError`,
`IamOperandTypeError`, `IamPatternRefusedError`, `IamUserSourcedPatternError`,
`IamRoleLimitExceededError`, `IamPolicyCompileError`, `IamValidationError` — is
gone, root export included. Every one of those throws, and every other throw
across the package, is now a single `IamError` carrying a `.code` from the new
`IAM_ERRORS` map. `.name` is `'IamError'` on all of them, so code that switched
on `.name` to tell error kinds apart stops distinguishing anything; code that
read `.message` now gets the bare code (`'IAM_CONDITION_OPERAND_TYPE'`, not the
old field/operator sentence) — `explain()`'s `conditionError` trace field
inherits this, so a rule that Indeterminates now traces to the code alone,
not the old prose. Whatever the deleted classes carried as properties
(`.policyId`, `.field`, `.reason`, and so on) lives in `.meta` instead, read
with the new `metaOf(err, code)` — root-exported alongside `IamError`,
`IAM_ERRORS`, `hasIamErrorCode`, `throwIamError`, `asIamError` and
`rethrowIamError`. `hasIamErrorCode(err, code)` replaces every adapter's old
bespoke `isXxx`/`instanceof` check for matching an error thrown by a
separately-installed copy of this package.

**Behaviour and type changes to be aware of.** The Nest action fallback and the
drizzle re-grant semantics both change observable behaviour, in the fail-closed
direction in the first case and from a lost write to a completed one in the
second. The HTTP list change turns a silently empty catalog into a thrown error,
which is the point, but a server answering with an envelope will now fail loudly
where it used to fail quietly. The same applies to role rows across every
adapter: `listRoles` and `getRole` now reject where they used to skip the row or
answer `null`, so a store with a corrupt role row stops serving decisions instead
of serving one with the denies missing. An empty `secret` on the redis
invalidator is now a constructor error. `IamAdminAudit.Target` narrows from five members to
`'policy' | 'role' | 'role-assignment'`; consumers receive these events rather
than construct them, so a narrowing removes switch arms that could never be hit,
but it is a public type change. The release bump is left as it stands for you to
decide.
