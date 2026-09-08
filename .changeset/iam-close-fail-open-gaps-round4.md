---
'@gentleduck/iam': major
---

Close three fail-open gaps and finish the invalidator log redaction.

**`RuleBuilder.build()` refuses a builder that was never configured.** The
defaults are the broadest possible grant — `allow` on `['*'] x ['*']` with
`{all:[]}` conditions, which evaluates true — so `.rule('x', (r) => { ...forgot... })`
silently pushed an unconditional allow-everything rule into the policy.
`PolicyBuilder.rule()` had claimed for some time that `build()` already refused
this; it did not. The validator does detect the shape (`BROAD_ALLOW`) but emits
it as `type:'warning'`, and `build()` keeps only `type:'error'`, so the verdict
was computed and discarded with no console output and no return channel.

The refusal is deliberately narrower than promoting `BROAD_ALLOW` to an error:
it targets *silence*, not breadth. A deliberate broad grant still builds — say
`.allow()` — and `validatePolicy` still accepts stored policies carrying one, so
existing policy data is unaffected. `desc()`, `priority()` and `meta()` annotate
a rule rather than shaping it and do not count as configuring it; `forScope('*')`
does count, because it is an explicit statement about scope even though it
narrows nothing.

**BREAKING:** `defineRule(id).build()` and `new RuleBuilder(id).build()` now
throw unless at least one of `allow`, `deny`, `on`, `of`, `forScope`, `when` or
`whenAny` was called.

**The `allowFailOpen` gate now covers every public evaluator entry point.**
`evaluate.public.ts` gated `iamEvaluate` / `iamEvaluateFast` and asserted its
wrappers were "the only route to the evaluator from outside the package". They
were not: the barrel re-exported the raw single-policy `evaluatePolicy` /
`evaluatePolicyFast` straight from `./evaluate`, and both reached the package
root, so `iamEvaluatePolicy(policy, req, 'allow')` answered `allowed: true` with
no opt-in and no warning. All four are now gated and pinned together by one test,
because a half-gated boundary is what made the original claim false.

**BREAKING:** `iamEvaluatePolicy` / `iamEvaluatePolicyFast` throw on
`defaultEffect: 'allow'` unless the new trailing `allowFailOpen` argument is
`true`, matching `iamEvaluate` and `IamEngine`.

**`explain()` and `can()` agree on condition groups again.** `evalConditionGroup`
distinguishes `{}` ("no conditions", unconditionally true) from a group carrying
unrecognised keys (false, so a typo cannot turn a conditional allow into an
unconditional one). `traceGroup`'s fallback collapsed both to `false`, so
`explain()` reported a denial for a rule `can()` allowed. The fallback now
delegates to `evalConditionGroup` rather than reimplementing it — this is the
third time a hand-copy of the decision logic has drifted from it.

**The Redis invalidator no longer logs raw tenant-bearing channels.** The earlier
redaction covered the two drop-warning sites only; `reportSubscribeFailure` and
the unsubscribe rejection handler still logged `JSON.stringify(channel)`, so a
NOAUTH, a wrong ACL or a reconnect window wrote the tenant id to stderr. Reaching
it needs no PUBLISH rights at all — a broker hiccup is enough.

**The untouched-builder refusal now gates on what the rule became, not on which
methods were called.** Three shapes still built the exact allow-everything rule
it was added to refuse. The one that matters is `.forScope(...tenantIds)` with a
runtime-empty array: `forScope` set the flag before discovering it had no scope
to apply, so a rule meant to be tenant-restricted built global and passed the
guard. `forScope` now throws when called with no scopes at all - a restriction
that names nothing can only be a call-site bug, and `'*'` is how "every scope"
is said out loud. `.when(w => w)` was the same shape: an empty `all` group is
`.every` over nothing, which is `true`, so it matches every request; an empty
callback no longer counts as configuring the grant. `.whenAny(w => w)` is left
alone deliberately - `.some` over nothing is `false`, so an empty `any` group
matches nothing and fails closed.

**BREAKING:** `.forScope()` with no arguments throws.

**A `$`-sourced `matches` operand is refused at validate time.** `evalCondition`
returns `false` for one without looking at the request - correctly, since a
caller-supplied pattern is a ReDoS vector - which makes the condition false for
every request that will ever arrive. `validate.libs.ts` skipped these with the
comment "Non-string / $-resolved values are caught elsewhere"; nothing caught
them. A `deny`-when-`matches` rule written against a request attribute validated
clean, stored clean, and never fired. New code `ERR_REGEX_USER_SOURCED`, an
error, matching the two sibling pattern checks beside it. The three literal
cases (uncompilable, over-long, catastrophic) were already errors and are
unaffected.

**`explain()` no longer throws where `can()` denies.** `evaluate` absorbs a rule
that throws as Indeterminate - the policy votes deny if it carries any deny
rule, else casts `defaultEffect` - while `explainEvaluation` had no `try` at
all. On an unknown operator, `conditions: {all: null}` or a non-array group it
raised out of the caller: a diagnostic failing on precisely the input it exists
to explain, which is also the shape a hand-edited store row produces. The
failure is now recorded on the rule trace as `conditionError` and the policy
casts the same Indeterminate vote, reusing decision's own `policyHasDenyRule`
rather than reading the rule list a second time. This is the fourth drift
between these two paths and the third caused by a hand-copy.

`Explain.IRuleTrace` gains an optional `conditionError`.

**A dangling inherited role id no longer becomes a phantom role.**
`resolveEffectiveRoles` added a role id to the effective set *before* looking it
up, so an id reached through `inherits` that no role defines landed in
`subject.roles` carrying no permissions - and a hand-written ABAC rule testing
`subject.roles contains 'ghost'` fired on it. The route in is ordinary: delete a
role while another still names it in `inherits`. `deleteRole` cascades the
*assignments* on every adapter, so the direct grant goes; the inherited id did
not. `validateRoles` already calls this state `DANGLING_INHERIT` with
`type: 'error'`, so dropping it is not a new opinion about the data. Directly
assigned ids are kept whether or not the catalog defines them - that is a row an
operator wrote, not one derived from one.

**BREAKING:** `getEffectiveRoles` and `subject.roles` no longer contain
inherited role IDs that no stored role defines.

**Prisma translates `P2003` into the shared unknown-role refusal.** An unknown
role produced ``Foreign key constraint failed on the field: `roleId` `` off the
driver - naming a column of a schema the operator may not have written, in a
string nothing can branch on - while four adapters raised one shared sentence.
The driver error is preserved as `cause`. The compliance suite gained the clause
that would have caught it, plus one requiring the refusal not to echo the
caller-supplied role id back into an operator log.

**BREAKING:** `runAdapterCompliance` takes a third `IComplianceOptions`
parameter. `delegatesRoleExistence: true` waives the *wording* of the
unknown-role refusal (not the refusal) for an adapter that delegates role
existence to a remote server - the HTTP adapter.

**Nest denies a handler whose `@IamAuthorize` metadata is unreadable.** The
guard read the metadata and treated anything falsy as "no decorator present",
so a handler decorated with metadata that did not survive serialisation - or
that arrived as `null`, `0` or `''` - was allowed through with no authorization
call at all. Presence and readability are now separate questions: no decorator
still allows, unreadable metadata routes to `onError` and denies.

**`iamOptionalStringField` refuses an explicit `null`.** It treated `null` as
"absent", so `{"scope": null}` on an admin route meant *unscoped* - a global
grant - where the caller had written something that reads like "no value". Omit
the field to mean unset.

**BREAKING:** an admin request body carrying an explicit `null` for an optional
string field is now a 400 instead of being silently read as absent.
`IamValidationError` gained `statusCode = 400`, which is the property Nest's
base exception filter duck-types.

**The admin audit trail records a refusal as a refusal.** `iamWithAdminAudit`
set `success: true` whenever the handler returned normally, and a handler that
returns a 400/403 response object returns normally - so a rejected mutation was
written to the audit log as a successful one. `savePolicy` / `saveRole` also
record the target id now, via the new `iamAuditIdOf`.

**The Redis invalidator reports dropped inbound messages.** A `secret` present
on some nodes and not others makes every peer invalidation drop in both
directions for the whole rollout; caches never converge and the failure is stale
*allow*. The only report was a `console.warn` coalesced to one line per minute.
New `onMessageDropped(reason, channel, suppressed)` hook. Separately, the
coalescing latch was keyed on the channel alone, so attacker-driven inbound
drops and publish failures shared one 60s budget - one junk message a minute
suppressed the publish-failure warning for a concurrent broker outage. The two
kinds now have separate keys.

**Derived caches inherit their inputs' expiry.** `IamLRUCache` gained
`expiresAt(key)`, and the RBAC-policy, merged-policy and compiled-table caches
now cap their own entries at the oldest input's expiry rather than restarting
the TTL clock. A policy-only invalidation used to re-age the role snapshot,
which was measured serving a stale allow for 118s under a 60s TTL.

**`IamSubjectsPanel` carries the devtools guard itself.** `package.json` exports
every panel individually under `./dt`, and the subjects panel - the only one
that writes, calling `assignRole` / `revokeRole` / `setAttributes` - had no
`isDevtoolsAllowed` anywhere in its path when imported directly.

**The admin read routes run the same authorization phase as the writes.**
Express, hono and next gated `GET /policies` and `GET /roles` on `authorize`
alone while nest ran the CSRF check too, so an operator whose `csrfCheck`
carried any part of an authorization decision had it enforced on reads on one
of four adapters, undocumented. All four now run `iamRunAdminAuthz`. This is
not a new refusal for API clients: `iamDefaultCsrfCheck` returns `true` when
there is no `Sec-Fetch-Site` header at all, which is every non-browser caller.

**Nest answers a failed admin mutation the way the other three do.** It threw
the handler's own error untouched, so an internal message reached the client -
in one of this package's own tests, a fake SQL string naming a password column.
Express, hono and next all answer a fixed `Internal server error`. Nest now
throws that, with the original attached as `cause` so a logger loses nothing,
and `includeErrorMessage` governs the audit string only, as it does elsewhere.
`IamNest.IAdminOptions` gained `onUnauthorized`, `onForbidden` and `onError`,
which the other three adapters already had.

**BREAKING:** a Nest admin handler that throws now surfaces
`Internal server error` (500) rather than the original error. Read `cause` for
the original. A validation failure surfaces as 400, as on the other adapters.

**One malformed admin request now gets one answer on all four adapters.**
`POST /subjects/:id/roles` with `{"roleId": ""}` was a 400 on hono, which
hand-rolled its checks inline, and a 500 on express, next and nest, whose shared
validators threw a bare `Error` that every generic `catch` routes to `onError` -
paging an operator for a client's typo and telling the client to retry something
that will never succeed. `{"roleId": "   "}` was a *write* on all four: the
checks read `length === 0`, so a blank id became a real grant on a role that
renders as nothing at all in an admin UI, while `iamIsNameableActor` next to
them had required `.trim().length > 0` all along. And hono capped ids at 128
characters where the other three applied no cap and let the engine's 1024
decide.

`iamRequireStringField`, `iamOptionalStringField` and `iamRequirePathParam` now
refuse a blank value and cap at `IAM_MAX_ADMIN_FIELD_LENGTH` (1024, the engine's
own cap, so the edge refuses exactly what the engine would), and they throw
`IamValidationError` so all four adapters answer 400 through the branch they
already had. Hono uses them instead of its inline copy.

**BREAKING:** `IamValidationError.kind` gained `'request'`, alongside `'policy'`
and `'role'`. A whitespace-only `roleId`, `scope` or `:id` is now a 400 instead
of a grant, and a bad admin field is a 400 instead of a 500 on express, next and
nest.

**A body that is not JSON is a 400 on hono and next.** Both call `req.json()`
inside the audited handler, so a truncated upload - or a form post carrying a
JSON content-type - raised a `SyntaxError` out of the handler into the generic
`catch`, which answered 500 and handed the parse error to `onError` as though
the package had broken. Express and nest never saw it, because their hosts parse
the body first. New `iamReadJsonBody` wraps the framework's own parser; the
refusal deliberately does not repeat the parser's message, which quotes the
offending bytes into an operator's log.

**Test-suite gaps closed alongside the fixes above** (no runtime behaviour
change): the e2e tier now runs in CI - nineteen files and roughly seven hundred
tests previously executed in no workflow at all, because `bun run test` excludes
`**/*.e2e.test.ts` and nothing invoked `test:e2e`. The HTTP e2e sweep gained a
sixth listener that opts into proxy trust, because every `environment.ip`
assertion in that file compared five integrations that all report `undefined`,
and deleting the IP derivation outright left the section green. The two verdict
suites now name the verdict they expect rather than only requiring the two
engines to match. And the fast/slow evaluator delegation for throwable policies
is pinned directly: deleting it leaves the 6000-iteration property oracle green,
because on any iteration with a throwable policy the "fast path" *is* the
interpreter.

**And the tier that CI now runs was quietly smaller than it looked.** Five e2e
files decided whether to run by shelling out to `docker info` with a
five-second budget of their own, rather than using the shared thirty-second
probe. On a machine already running the e2e stack the daemon takes longer than
that, so the copies answered "docker is down": the redis adapter suite dropped
twenty-four cases and the invalidation failure-modes suite dropped ten, in a
run that reported `609 passed | 26 skipped` and exit 0. Their own reachability
guards read the same wrong answer and agreed the skip was expected. All five
now call the shared probe, which is memoised so the gate and the guard cannot
reach different verdicts - and the guards no longer consult it at all under
`CI`, where the workflow provisions the backends before vitest starts and
"absent" is a broken runner rather than a reason to be quiet. The two
invalidation suites had no guard at all; the comment above one of them said
"fail loudly, not silently" next to a gate that could only do the opposite.
With the probe fixed the same command collects **706** tests and skips none.

Three harness bugs surfaced by that: `assertE2eReachable` awaited a
thirty-second probe inside a case with vitest's five-second default, so it
failed as a timeout on exactly the busy daemon it was written for
(`scope-prod-parity` red on that line with its eleven cases passing beside it);
`whilePaused` returned as soon as `docker unpause` did, without waiting for
Postgres to serve again the way `whileStopped` already did, so the recovery
case read a fail-closed deny as a failure to recover; and the shared compliance
matrix registers ~100 cases with no explicit timeout, which is right against
the in-memory fake and wrong against a container sharing the machine with every
other suite - one round trip took 5.88s and was reported as a failure.

**A denylist with an operand typo admitted everyone, and validation was not in
front of it.** `nin` returns `true` when its operand is not an array, so
`allow if tier nin 'banned'` - the author meant `['banned']` - satisfies the
guard for every subject it was written to exclude. The operand-type matrix in
the validator refuses that, and the package's own test said the verdict was
"unreachable only because the validator refuses the operand first". It is not:
`validatePolicy` runs on `admin.savePolicy` and `admin.import`, while
`loadPolicies` does not validate at all. Measured end to end, with no database
and nothing hand-edited - a policy seeded through the documented
`IamMemoryAdapter` constructor let a banned subject through `engine.can`. The
same door is an operator's `INSERT`, a seed script, a migration, or a row
written by a version that predates the rule.

The evaluator now applies the matrix itself and throws `IamOperandTypeError`
rather than answering, which `evaluate` absorbs the way it already absorbs an
unknown operator - Indeterminate, reported through `onPolicyError`, never
`false`, because answering `false` retires a deny rule just as quietly. The
table moved to `conditions/conditions.libs` beside the operators it describes
and the validator imports it, so the write-time check and the read-time check
cannot drift. Because `condVal` is the *resolved* operand, this also covers
what the validator cannot see: a `$`-prefixed reference is skipped there, since
its type is unknowable at authoring time, and lands here as whatever the
request actually carried. **BREAKING** for anyone whose store holds a policy
the validator would have refused: that policy now denies, loudly, instead of
granting.

**The devtools production guard stood in front of one panel out of five.**
`isDevtoolsAllowed` is default-block and well argued - it blocks unless both
`NODE_ENV` and the engine's own mode give a positive development signal - and
its docblock says it exists so "the policy/role/subject **readers** cannot leak
into raw-browser bundles (CWE-200 / CWE-489)". Two of those three readers never
called it. `package.json` publishes `./dt` and `src/dt/index.ts` exports all
seven panels individually, so importing one directly is a supported thing to
do, and through that route `IamPoliciesPanel` renders the entire policy corpus
from `engine.admin.listPolicies()`, `IamRolesPanel` the whole role catalog, and
`IamDecisionInspector` answers `engine.explain()` for any subject, action and
resource typed into it - each blocked through `IamDevtools` and wide open
through its own export. `IamSubjectsPanel` had already been given the guard for
exactly this reason; the reasoning was never carried to its siblings.

All four panels that are handed an engine now call the guard themselves, as
`IamSubjectsPanel` does. `IamFlowPanel` and `IamTraceTree` are untouched: they
take a recorder and a result and never reach an engine. The "only panel that
writes" framing is also retired - `IamMetricsPanel`'s Reset button calls
`engine.stats.reset()`. Guarding is now enforced by a source sweep as well as
by render tests, so a panel added later that reaches for the engine fails until
it carries the guard.

**The devtools could not render outside this monorepo at all.** `./dt` is a
published export, and `@gentleduck/registry-ui` and `@gentleduck/libs` were
*optional* peer dependencies - but six devtools modules imported them
unconditionally, so `import '@gentleduck/iam/dt'` threw `ERR_MODULE_NOT_FOUND`
for any consumer who had installed the package and not those two. The modules
that did resolve still rendered wrong: their Tailwind utility classes only name
real CSS if the consumer's Tailwind is configured to scan this package's
`dist`, and the `iam-dt-*` rules read `var(--card)`, `var(--border)` and
`var(--foreground)` out of the host theme with no fallback. None of this is
visible from inside the monorepo, where both peers are installed and Tailwind
does scan the source, which is why it survived.

The devtools now own their appearance outright. `lib/styles.ts` carries the
whole visual layer - every colour an `--iam-dt-*` token it defines itself,
every component a class it ships - injected as a single `<style>` tag, with a
scoped reset so a host's `button {}` cannot reach inside. There are two
themes: `data-iam-dt-theme` pins one and the new `theme` prop sets it,
defaulting to `'auto'`, which follows `prefers-color-scheme`. Tokens are
declared only on the outermost `.iam-dt`, because each panel carries the class
(each is exported individually and may be its own root) and a nested block
would re-derive the theme and overrule an explicit one. The action, resource,
allow and deny colours were hardcoded hex tuned against a dark ground and sat
at roughly 2:1 on a white one; both palettes now come from a set with worked-out
contrast in each direction. `@gentleduck/registry-ui` and `@gentleduck/libs`
are gone from `peerDependencies`, `peerDependenciesMeta` and `devDependencies`,
along with a `@gentleduck/variants` entry that was listed as an optional peer
without ever being declared or imported.

Two things that were broken rather than merely coupled: a panel imported
directly injected no stylesheet at all, since only the two shells called
`ensureStylesInjected` - every panel now does, through `useIamDevtoolsStyles`.
And the accessibility of the overlay: the tab strip is a real `tablist` with
arrow-key navigation (previously six buttons, five of them unreachable from the
keyboard once the strip claimed the role), Escape closes the panel and returns
focus to the launcher, opening moves focus into it, the resize edge is a
focusable `separator` that responds to arrow keys, Home and End, `Section` and
the JSON tree report `aria-expanded`/`aria-controls`, `Field` associates its
label with its control, filter pills report `aria-pressed`, alerts announce,
icons are hidden from assistive technology, and every animation stops under
`prefers-reduced-motion`.

Regression tests in `dt/__tests__/dt-selfcontained.test.tsx`: a source sweep
that fails on any import of the two optional peers, a sweep of the stylesheet
for any `var()` it does not define itself, a check that the token blocks stay
root-scoped, a cross-check that every `iam-dt-*` class the components emit has
a rule in the sheet that ships with them, and a render of each panel on its own
asserting it is its own themed root. Each has a positive control, because an
empty sweep satisfies every one of them.
