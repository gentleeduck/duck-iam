# @gentleduck/iam

## Unreleased

### Minor Changes

- ff6f112: Close five ways the policy builder could emit something other than what the author wrote.

  **A condition callback that returns a group is no longer discarded.**
  `RuleBuilder.when()`, `RuleBuilder.whenAny()`, `RoleBuilder.grantWhen()` and
  `PolicyBuilder.rule()` used the builder they passed in and ignored the callback's
  return value. The reusable-group idiom returns one, so
  `.when(() => sharedOwnerOrAdmin())` authored to `{ all: [] }` - and `all` of
  nothing is true, making the rule fire unconditionally: an allow rule granted to
  everybody, a deny rule denied everybody. The returned builder is now honoured. A
  callback that both chains onto its argument _and_ returns a different builder
  throws, because there is no answer to which group was meant.

  **Built condition groups no longer alias the builder's array.** `buildAll()`,
  `buildAny()` and `buildNone()` snapshot. Reusing a `When` after building used to
  reach back into rules that were already finished.

  **`When.roles()`, `When.scopes()` and `When.resourceType()` refuse zero
  arguments.** They emitted a membership test against an empty list, which can
  never match - on a deny rule that removes the guard. Pass at least one value, or
  `.in(field, list)` when the list is computed and may legitimately be empty.

  **The builders emit absent optional keys, not keys holding `undefined`.**
  `description`, `targets` and `version` on policies, `description`/`metadata` on
  rules, `description`/`inherits`/`scope`/`metadata` on roles. A key holding
  `undefined` survived in the memory, file and http stores and disappeared through
  every JSON- or `jsonb`-backed one, so the same authored policy read back unequal
  depending on where it had been. `version` in particular is now left out when
  unset: the `version: 1` default belongs to the store, and a builder that
  pre-empted it made "never set" indistinguishable from "set to 1".

  **Breaking:** `when()`'s type parameters were reordered to
  `when<TAction, TResource, TRole, TScope, TContext, TActiveResource>` so they name
  the slots they fill. They previously ran `TAction, TResource, TScope, TRole`,
  which let a scope be passed to `.role()` and a role to `.scope()`. Only callers
  who pass all four explicitly are affected; inference is unchanged.

- 3de4298: Make the HTTP boundary's refusals actually refuse.

  **A wildcard rule turned every unmappable request back into an allow.** The
  framework adapters map an HTTP request to an `(action, resource)` pair, and some
  requests cannot be mapped: an unmapped method, or a path this layer and the
  router downstream would read differently. Both were expressed by handing the
  engine a sentinel _string_ - `IAM_UNKNOWN_ACTION`, `IAM_UNKNOWN_RESOURCE` -
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

- 8c131a4: Grant writes now record who made them, `engine.admin` emits a typed mutation event for every write, and `mode` defaults to `'production'`.

  **Actor provenance.** `IAssignOptions` gains `actor?: string`, and `revokeRole` / `revokeRoles` gain a matching `IRevokeOptions`. `savePolicy`, `saveRole` and `setSubjectAttributes` take a new `IActorOptions`. Every table in the drizzle and Prisma schemas has declared `created_by` / `updated_by` for as long as it has existed and nothing ever filled them - eight columns per dialect promising a provenance the API could not produce. They are written now: `created_by` on the row a call inserts, `updated_by` on the row it overwrites, so an edit records its editor without rewriting the original author. Both are written by spread rather than as an explicit null, so a table that predates the columns is untouched unless the caller names an actor.

  `actor` is deliberately outside the `ASSIGN_OPTION_FIELDS` allow-list that `iamAssertNoAssignOptions` guards. Dropping `expiresAt` changes what the store answers; dropping `actor` does not, because the event carries it regardless.

  **Mutation events.** Wire `hooks.onMutation` to receive a closed discriminated union - `role.assigned`, `role.revoked`, `role.scope-changed`, `role.saved`, `role.deleted`, `policy.saved`, `policy.deleted`, `attributes.set` - each carrying `at`, the optional `actor`, and the subject/role/scope the write touched.

  The library owns the event and the actor and ships no history table: retention, redaction and GDPR erasure are compliance decisions the consuming application must own. There is no way to register your own events on this bus; the union stays closed so a `switch` on `type` stays exhaustive across versions.

  Two details worth knowing: `attributes.set` carries key names and never values, because attribute bags routinely hold personal data and the event is likely headed for a durable log. And under `withTransaction`, events buffer alongside invalidations and are emitted only on `flush()` - a rolled-back grant leaves no history.

  **Breaking:**

  - **`mode` now defaults to `'production'`.** A consumer who never set it was running a production authorization engine that allocated a rich `Decision` on every call. Three consequences: `can()` / `check()` return `boolean` rather than `IDecision` unless you opt in; `policyCombine: 'first-applicable'` now throws at construction, since the production fast path cannot represent it; and devtools, which refuses a production engine, is now off unless you set `mode: 'development'`.
  - **Explicit type arguments need a fifth.** TypeScript uses a type parameter's default rather than inferring it when the argument list is partial, so `new IamEngine<Action, Resource, Role, Scope>({ ..., mode: 'development' })` no longer typechecks. Write `new IamEngine<Action, Resource, Role, Scope, 'development'>(...)`, or drop the explicit arguments and let all five infer.
  - **`afterEvaluate` and `onDeny` now fire in production too.** They were documented and implemented as development-only, which put the audit and alerting hooks in the mode nobody runs in production. The production decision is verdict-only - `allowed`, `effect`, `duration`, `timestamp`, and a `reason` that says so - because the compiled table erases policy identity at compile time and that erasure is the optimisation. `policy` and `rule` are absent rather than fabricated. Nothing is allocated unless one of the two hooks is wired.
  - **`maxConcurrentSubjectLoads` defaults to `512`** instead of `0` (unbounded). Only distinct, never-before-cached subjects count toward it, so reaching 512 means a cold-start herd rather than normal traffic. Shedding denies legitimate requests, so the bound is deliberately generous; set `0` to restore unbounded explicitly.

  **Also:**

  - `IamEngine.setInvalidator(invalidator | null)` attaches, replaces or detaches an invalidator after construction, for callers whose Redis client is built after their engine. It unsubscribes the previous one first and validates the shape, so a malformed object fails loudly instead of surfacing later as invalidations that never arrive. `IConfig.invalidator` still works and now routes through it.
  - `iamScopeAncestors` and `iamScopeCovers` are exported. Callers doing scope-aware rank or reach calculations had to reimplement the walk, and any reimplementation drifts from the relation the engine matches with.
  - The drizzle adapter warns once per process, at construction, when `ops.isNull` or `ops.or` is missing. Both omissions are correct but silently slow - without `or`, `revokeRoleMany` degrades to one `DELETE` per row; without `isNull`, `updateAssignmentScope` falls back to revoke + assign, two writes with a window where the grant does not exist. Neither can be derived: `eq(col, null)` is not `IS NULL`, and there is no way to synthesise an `OR` builder from `eq` and `and`.

  **Production and development now agree on two cases where they did not.** Both were found by running the same catalog through a production engine and a development engine and comparing verdicts; both had production granting access development refused, on identical data, with no malformed catalog anywhere.

  - **A throwing role permission no longer voids unrelated grants.** `rolesToPolicy` folds every role permission into one generated `__rbac__` policy, and the interpreter caught a throwing condition at whole-policy scope - so one rotten permission denied a subject an unconditional grant held through a different role, while the compiled table answered allow from the grant mask before it ever reached the bad condition. A rule that throws inside that generated union now abstains and is reported through `onPolicyError`, matching the table. This is safe only there: `rolesToPolicy` emits `effect: 'allow'` and nothing else, so a skipped rule in an allow-only union can cost a subject a grant but can never suppress a denial. An authored policy still fails closed at whole-policy scope, because its vote may have been a deny.
  - **Role permission conditions get the same nesting budget in both modes.** `rolesToPolicy` nests a permission's condition group one level inside the generated rule, so the interpreter reached it at depth 1 while the compiled table, which stores the group raw, started it at 0. Authors got ten usable levels in production and nine in development: at exactly `MAX_CONDITION_DEPTH` the table allowed and the interpreter denied, while depths on either side agreed. `validateRole` already validated at depth 1, so the table was the outlier; it now starts there too, via the new exported `IAM_RBAC_CONDITION_DEPTH`.

  **Schema fixes.** The three drizzle schemas are three hand-written files describing one logical schema and nothing compared them, so they had drifted:

  - MySQL's `iam_roles.inherits` was `NOT NULL` with no default, while Postgres and SQLite default it to `[]`. The same insert succeeded on two dialects and failed on the third.
  - `ch_iam_roles_scope_not_blank` and `ch_iam_assignments_scope_not_blank` existed only on Postgres, so a whitespace-only scope was storable on MySQL and SQLite and rejected on Postgres.
  - MySQL lacked `idx_iam_assignments_subject_scope`, leaving the scoped-subject lookup - the hot read - to a subject scan plus a filter. It is added unfiltered there, MySQL having no partial indexes.

  A new `schema-parity.test.ts` compares columns, insert-required columns, indexes, CHECKs and foreign keys across all three dialects, with an explicit allow-list for the handful of entries a dialect genuinely owns alone (Postgres GIN indexes, SQLite's algorithm CHECK standing in for the others' enum type). It also pins `src/test/pg-e2e-schema.sql` - self-described as a hand-kept mirror, with nothing keeping it honest - against the Postgres schema module.

  The Prisma reference schema gains the provenance columns, `updated_at` on assignments, `created_at` on subject attributes, and the `role` / `(subject, scope)` indexes the drizzle schemas already had. Its header now spells out what Prisma cannot express - CHECK constraints, partial indexes - and, importantly, that `@@unique([subjectId, roleId, scope])` does not prevent a duplicate _unscoped_ grant, because SQL unique indexes do not collapse NULLs. The adapter closes that hole with a read-then-write; the comment exists so nobody "simplifies" it back to a bare `create`.

  **Breaking: a role must exist before it can be granted.** `assignRole` (and `assignRoles`) now throws when no role is stored under the given id, on every adapter. This was already true on drizzle and Prisma, whose schemas carry the assignments-to-roles foreign key, and silently accepted on memory, file, redis and HTTP: the row landed, `getSubjectRoles` returned the id, and `resolveSubject` dropped it again because no definition resolves — so a typo'd role id reported success and granted nothing. Provisioning code that assigns before saving the role must now save first. The drizzle adapter also translates the driver's foreign-key error into that same refusal, keeping the original as `cause`; before, an operator saw `Failed query: <sql>` with the constraint reachable only on `.cause`.

  **Breaking: the unique indexes on policy and role `name` are gone.** `uq_iam_policies_name` and `uq_iam_roles_name_scope` existed only on the drizzle Postgres schema. Nothing in this package resolves a policy or role by name — `id` is the key everywhere — so they protected a field no code reads while making a write the adapter contract mandates impossible on Postgres alone. Existing databases keep them until you drop them; nothing in the library depends on either behaviour.

  **Breaking: `iamExtractEnvironment` no longer guesses the client IP.** It reported one from `req.ip`, `x-forwarded-for` or `x-real-ip`, which meant five HTTP integrations gave five different answers for the same request, and — with nothing in front of the app — let a client set `X-Forwarded-For` and satisfy an IP-conditioned policy. `environment.ip` is now `undefined` unless the app opts in: pass `{ trustProxy: true }` as the second argument, or supply the environment yourself through the integration's `getEnvironment`. Hono's `trustCloudflareHeaders` is that opt-in there. The normalisation is unchanged behind the flag.

  **Breaking: deleting a role now revokes the grants that named it.** `deleteRole` is a cascade on every adapter, matching what `fk_iam_assignments_role ON DELETE CASCADE` already did on drizzle and Prisma: the same call left `getSubjectRoles` returning the deleted role on memory, file, redis and HTTP and `[]` on the SQL adapters. The orphan was not inert — `resolveSubject` ignored it, but recreating a role under the reused id handed it back to everyone who once held it, with no operator granting anything, and `assignRole` now refuses to create the very row `deleteRole` was leaving behind. The redis adapter reaches the assignment sets with a `KEYS` sweep on that one admin-rate call; a client that does not expose `keys` gets the role deleted and a report through `onPolicyError` saying the grants were not. An HTTP server is expected to cascade on `DELETE /roles/:id` — see the reference server in `http-compliance.test.ts`.

- 70a9e4d: A malformed admin request body now answers 400 instead of 500.

  `engine.admin.savePolicy` and `saveRole` validate before they write, and signalled
  a rejection with a bare `Error`. Every HTTP integration catches whatever a handler
  throws and routes it to `onError`, which answers 500 — so a body the validator
  refused, which is the client's mistake, was reported as the server's. The write
  was correctly refused either way, so this was never a way past validation; but a
  500 tells a caller to retry a request that can never succeed, and hides a client
  bug behind an apparent outage.

  Rejections are now `IamValidationError`, carrying `kind` (`'policy' | 'role'`),
  the validator's `issues`, and `status: 400`. It extends `Error`, so existing
  `instanceof Error` checks and the exact message text still hold.

  - **express, hono and next** answer `400 { error: 'Invalid policy', issues: [...] }`
    and no longer route the failure through `onError`.
  - **Nest** hands errors to its own exception filter, which only maps
    `HttpException`, and this package does not depend on `@nestjs/common`. Read
    `status` in a filter of your own:

  ```ts
  if (iamIsValidationError(err))
    throw new BadRequestException({
      error: `Invalid ${err.kind}`,
      issues: err.issues,
    });
  ```

  A genuine server fault is still a 500, and the `onAdminMutation` audit event
  still fires with `success: false` either way.

- 3de4298: The Prisma adapter no longer invents keys a stored role does not have.

  `toRole` mapped an absent or null `inherits` column to `inherits: []`, so a role
  read back through Prisma was not the role the other adapters returned for the
  same row — a caller distinguishing "inherits nothing" from "does not declare
  inheritance" saw the two collapse, and only on this adapter. Absent columns now
  produce absent keys, matching the memory, Drizzle and Postgres adapters.

  If you relied on `role.inherits` always being an array, read it as
  `role.inherits ?? []`.


- Both engine modes now evaluate through the compiled table.

  `mode: 'production'` used the compiled table and `mode: 'development'` used the interpreter, so a disagreement between the two was invisible until it reached production - and it reached production as an _allow_ against a development run that denied. That single shape accounted for five separate defects in the round-3 audit.

  The table now produces the verdict in both modes. Development additionally runs the interpreter, because the table cannot explain itself: `CONST_ALLOW`/`CONST_DENY` cells are one `kind` byte and `allow` is a raw bitmask, so policy identity is erased at compile time. The interpreter supplies `reason`/`policy`/`rule`, the table supplies the verdict, and a disagreement is printed and thrown - a development-time failure instead of a production-only allow. `check()` returns the same `IDecision` it always did.

  Development is roughly 2.4x slower than production as a result. That is the trade: the second evaluator is what makes a divergence visible, and it does not run in production.

- More roles than the 32-bit grant mask can address now falls back to the interpreter instead of denying every request.

  `compileTable()` throws past 32 roles because role N and role N+32 would otherwise silently share a mask bit. That throw used to reach `authorize()`'s catch, so the whole deployment answered deny with no message unless an `onError` hook happened to be wired - a total authorization outage caused by a capacity limit of one representation.

  The engine now catches that error specifically, warns once, and runs the interpreter, which has no such limit. `preload()` resolves instead of throwing and `healthCheck()` keeps `ok: true` while reporting `compiledTable: { available: false, reason: 'role-limit-exceeded', roleCount, limit }` - correct answers, no fast path, and an operator who can see which.

  Every other compile failure still throws and still denies; a malformed policy is a bug, and answering it with a slower correct path would hide it.

### Patch Changes

- A policy the compiler cannot lower is now named.

  The compiler walks `policy.rules` and each rule's `actions`/`resources` directly, so a policy missing one of them threw from wherever the walk touched it first - `policy.rules is not iterable`, with no indication which of a tenant's policies was broken. The interpreter had always isolated a rotten policy and reported its id through `onPolicyError`, so moving both modes onto the table would have traded a precise diagnostic for an anonymous one. The shape check now runs before the walk, names the policy and the rule, and is forwarded to `onPolicyError` before the error is rethrown. The deny is unchanged.

## 5.8.1

### Patch Changes

- e47efb9: Time-boxed grants stop granting when they expire, not up to a `cacheTTL` later.

  **The subject cache now respects the grant's own window.** `IamLRUCache` gave every entry the engine's full `cacheTTL` (60s by default) with nothing tying it to the bounds the drizzle adapter filters on, so a grant with `expiresAt` kept answering _allow_ for up to a minute after it ended, and a grant with a future `startsAt` kept answering _deny_ for up to a minute after it opened. A 30-second break-glass grant was live for sixty. `IamLRUCache.set` takes an optional `notAfter`, caps the entry at the earlier of the two, stores nothing when the bound has already passed, and expires on `>=` so it agrees with the adapter's exclusive upper bound.

  **New optional adapter method: `getSubjectGrantBoundary(subjectId, opts?)`.** Returns the earliest _future_ `startsAt` or `expiresAt` among the subject's grants, or `null` when none has a bound. The engine asks for it alongside the reads it describes — no extra round trip — and caps the cache entry there. It is implemented by the drizzle adapter, the only one that stores the bounds; the other five omit it and continue to refuse the options outright. Custom adapters need no change, and gain the shortened cache by implementing it. A failure in the method costs caching only: the subject is not cached, the answer still comes from the store, and a warning names the method and subject.

  **`assignRole` refuses a window that can never be active.** `startsAt >= expiresAt` is an empty interval — the grant is stored and never live, while the call resolves and `engine.admin.assignRoles` reports `ok: true, applied: 1`. An `Invalid Date` in either field was passed to the driver rather than refused. Both are now rejected at the adapter boundary, on `assignRole` and on every row of `assignRoleMany`; the error names the fields and never the instants. The shipped pg/mysql/sqlite schemas already carried `ch_iam_assignments_starts_before_expires`, but the adapter can be pointed at a caller's own table, where the code is the only guard.

- Three fixes from the audit re-verification sweep.

  An error-reporting hook that throws no longer unwinds the evaluation it was
  reporting on. `onPolicyError` and `onRuleError` were called raw from inside the
  catch that implements the Indeterminate contract, so a hook whose metrics
  backend was down took the deny vote with it.

  The Redis invalidator's drop warning no longer prints the tenant id. The channel
  carries it, the warning is written on a path any holder of PUBLISH rights can
  drive, and stderr is the stream that gets shipped to shared aggregators; the
  tenant segment is now a stable digest instead.

  `explain()` and `can()` agree at the leaf. The trace evaluated conditions
  through the raw operator table, which skips the refusal of `matches` against a
  `$`-sourced operand, so a trace could report a condition as satisfied that the
  engine had refused - showing an operator the opposite of the decision they were
  debugging. Leaf verdicts now come from the decision path itself.

## 5.8.0

### Minor Changes

- 7202aa1: **Breaking:** scoped permission keys are now prefixed with `@`.

  `iamBuildPermissionKey` previously emitted `scope:action:resource[:resourceId]`, which is ambiguous with the unscoped `action:resource:resourceId` form - a three-segment key could not be parsed back without knowing which shape produced it, so a scope could be read as a resource id and vice versa. Scoped keys now carry an explicit `@` marker:

  - `org-1:manage:billing` becomes `@org-1:manage:billing`
  - `org-1:update:post:post-42` becomes `@org-1:update:post:post-42`

  Unscoped keys are unchanged. A literal leading `@` in a segment is escaped as `\@`, and `iamSplitPermissionKey` understands the escape. The new `iamParsePermissionKey` returns `{ scope, action, resource, resourceId }` or `null`, so consumers no longer have to split keys by hand.

  Anything that hardcodes a scoped key string - client-side permission maps, cached `can()` results keyed by string, fixtures - needs the `@` added.

### Patch Changes

- 2e5f5dc: Fix `resolveSubject` mistagging a role reached through cross-scope inheritance with the source assignment's scope instead of the role's own declared scope. A role assigned at one scope that `.inherits()` a role defined at another scope (e.g. a company-level role inheriting a marketplace-level role) had the inherited role silently invisible at the scope it actually belongs to - `enrichSubjectWithScopedRoles` filtered it out because it carried the wrong scope tag, so a policy check at the inherited-into scope only ever saw whatever lower-privilege role was directly assigned there, if any.

  Each role visited during the inheritance walk is now tagged with its own `IRole.scope`, falling back to the assignment row's scope only when the role declares none of its own - a no-op for roles with no cross-scope inheritance.

- 5c96bd5: Fix two places where a rule that was correct in development silently stopped applying in production.

  **`first-match` / `highest-priority` disagreed between the two evaluation paths on a priority tie.** Both algorithms resolve equal priorities by source order. The interpreter walks `policy.rules` directly and honoured that, but `evaluatePolicyFast` walks the rule index, which buckets literal-resource rules separately from wildcard-resource ones and visits the literal bucket first. A `deny read '*'` declared before an `allow read 'post'` at the same priority therefore denied under `mode: 'development'` and allowed under `mode: 'production'` - the deny disappeared exactly where it mattered most. `Evaluate.IIndexedRule` now carries the rule's index in `policy.rules`, and both tie-break sites in the fast path compare it, so bucket order no longer leaks into the decision. `deny-overrides` and `allow-overrides` were never affected; they are order independent.

  The `evaluate == evaluateFast` property oracle covered this shape in principle but drew priorities from 20 values, making ties too rare to hit it. It now draws from 4, so collisions are the common case.

  **The condition-nesting limit was off by one between the validator and the evaluator.** `evalConditionGroup` refuses a group at `depth >= MAX_CONDITION_DEPTH` and fails closed, while `validateConditionGroup` only errored at `depth > MAX_CONDITION_DEPTH`. A group nested exactly at the boundary therefore validated cleanly and then never matched. On an allow rule that merely failed closed, but a deny rule at that depth passed validation and silently stopped denying. Both comparisons are now `>=`, so anything the evaluator will refuse is reported as `LIMIT_EXCEEDED` up front.

- ec678af: Evaluation errors are now Indeterminate and fail closed instead of being silently skipped.

  A condition that threw - an unknown operator, a malformed `all`/`any`/`none` group, a regex rejected for being unsafe - was caught and treated as "policy does not apply", which quietly retired the deny rule that condition was guarding. An error inside a policy or compiled cell that carries a deny rule now vetoes the request. Allow-only policies and RBAC role permissions still skip, since an error there cannot grant anything.

  Also in this release:

  - `matches` uses a real catastrophic-backtracking detector instead of a naive nested-quantifier regex, and checks the compiled-pattern cache before running it.
  - Unknown condition operators and non-array condition groups throw a prefixed error rather than a raw `TypeError`.
  - HTTP method-to-action and pathname normalisation reject `//admin` and `/%61dmin` style bypasses; unknown methods and unresolvable resources map to explicit `IAM_UNKNOWN_ACTION` / `IAM_UNKNOWN_RESOURCE` instead of a permissive default.
  - User-Agent is capped at 2048 characters before it reaches the environment attributes.
  - The file adapter writes atomically via tmp-file + rename and serialises concurrent flushes; the redis adapter rejects an empty scope; the drizzle adapter rejects non-finite assignment bounds.
  - `preload()` builds the compiled table in production so a compile error surfaces at startup, and `healthCheck()` awaits it.
  - `pathCache` is no longer exported from `src/core/resolve`.

- 7a1ce88: `IamEngine.withTransaction(client)` binds reads and writes to a transaction you own, and `admin` gained batch forms that report per-row outcomes.

  The client is opaque to the library and handed straight back to your adapter. Writes go through `.admin`, the same interface as `engine.admin`, so there is one write surface rather than two. Reads on the bound view run against caches created for that transaction alone: an empty cache always misses through to the transaction-bound adapter, which is what makes a read-after-write inside the transaction correct, and the shared engine keeps answering from its own warm caches, which the transaction never pollutes.

  Cache invalidations - including the `config.invalidator` fleet broadcast - buffer in `pending`, de-duplicated, and fire on `flush()`. A rolled-back grant therefore never evicts another node's cache for a write that did not happen. The bound view drops the invalidator rather than reusing the parent's, so a facade built per transaction cannot leak a subscription; buffered entries broadcast through the parent engine on flush.

  Also in this release:

  - `admin` gained `assignRoles`, `revokeRoles`, `moveRoleScopes` and `invalidateSubjects`. Every row is validated before any is written, so a malformed row aborts the batch instead of half-applying it, and each affected subject is invalidated once however many rows named it.
  - Each outcome carries the `row` it answers rather than an id derived from it. A role assignment is identified by a `(subject, role, scope)` triple of free-form strings, and every encoding of three of those into one key is either ambiguous or unreadable - joining them with a space collided whenever an id contained one, and nothing rejects a space in a subject id. Outcomes stay in input order, so matching by index is exact too.
  - Both role writes are idempotent, so every row is `ok` - granting a role a subject already holds is success, matching the single-row method. Outcomes carry `changed` for the finer answer: `true` when the row accounts for a write the statement made, `false` when it was already in the requested state, and absent where the adapter could not say. It is read off a `RETURNING` clause on the write itself, so it costs no extra round trip; MySQL, which has no `RETURNING`, and adapters that loop the `void`-returning single-row methods leave it off rather than guess.
  - Every write is credited to exactly one row, the first that accounts for it. Listing the same triple twice reports `true` then `false` rather than both rows claiming a write the database made once, and revoking a role unscoped alongside a scoped row it already covers credits the wildcard. Neither batch is rejected.
  - The drizzle adapter collapses the writes into one `INSERT` and one `DELETE`. The `DELETE` needs `or` in the adapter's `ops` and revokes row by row without it.
  - The adapter contract gained an optional `withClient`. An adapter that cannot join a transaction makes `withTransaction` throw rather than silently leaving those writes outside it.

## 5.7.0

### Minor Changes

- 62e3d0b: Add an optional `IConfig.maxConcurrentSubjectLoads` cap (default `0` = unbounded,
  matching `adapterTimeoutMs`'s 0-disables convention) to bound the cold-flat herd.
  The herd is this: `inFlight.subjects` single-flights per subject and clears each
  key on settle, so steady state is bounded by concurrency - but on a cold start
  the peak is `arrival_rate x adapter_latency`, and the engine keeps issuing
  adapter reads as fast as requests arrive, with no load-shed. The cap bounds it.
  `resolveSubject` rejects a _new_ subject load once
  `inFlight.subjects.size` hits the cap, before touching the adapter - fail-closed
  load-shed, not a bounded queue, consistent with the engine's existing fail-closed
  posture. The rejection is a plain `Error` whose message contains `"subject load
shed"`, so it surfaces through `can`/`check`/`authorize`'s existing fail-closed
  `catch -> onError` path with no new wiring.

  A call that hits the subject cache or joins an already-in-flight load for the same
  subject never counts against the cap.

## 5.6.0

### Minor Changes

- `iam_assignments` gains `starts_at`, `expires_at`, and `attributes` columns across
  the pg, mysql, and sqlite drizzle schemas. `getSubjectRoles`/`getSubjectScopedRoles`
  now filter out assignments outside their `[startsAt, expiresAt)` window; a row with
  both NULL behaves exactly as before these columns existed.

  `IScopedRole` gains an optional `attributes` field, populated from the new column so
  a policy condition can read per-grant data (department, region, whatever the caller
  stores) as `subject.scopedRoles[].attributes`, distinct from the subject's own global
  attributes. A corrupted `attributes` value drops just that field and reports through
  `onPolicyError`, it does not fail the whole role.

  `ISubjectStore.assignRole` gains an optional fourth `opts: IamAdapter.IAssignOptions`
  parameter (`startsAt`/`expiresAt`/`attributes`), implemented by the drizzle adapter.
  Purely additive - every other adapter (memory, file, redis, prisma, http) still
  satisfies the interface unchanged.

## 5.5.1

### Patch Changes

- 86b6775: Drop `deletedAt` from `iamPolicies`, `iamRoles`, `iamAssignments`, and
  `iamSubjectAttrs`, added in 5.5.0, along with `IamDrizzleAdapter`'s opt-in
  `deletedAt IS NULL` read filtering. `deletePolicy`/`deleteRole`/`revokeRole` are
  hard-delete by explicit design (a soft-deleted policy/role name couldn't be reused,
  and a revoked assignment has no reason to be retained), and subject attributes have
  no delete operation at all - none of these columns would ever have been set by
  anything in this codebase.

  `ops.isNull` stays on `IamDrizzleAdapter`'s config: `updateAssignmentScope` still
  needs it to match a global (unscoped) assignment correctly, independent of the
  removed soft-delete filtering.

## 5.5.0

### Minor Changes

- 2853214: Add `engine.admin.updateAssignmentScope(subjectId, roleId, fromScope, toScope, actor?)`
  to move a role assignment to a different scope in one write instead of
  revoke + assign.

  `IamAdapter.ISubjectStore` gains an optional `updateAssignmentScope`. When an adapter
  implements it, the engine uses it directly; when it doesn't (or it returns `false`
  because nothing matched `fromScope`), the engine transparently falls back to
  revoke + assign, so the call always succeeds either way.

  Implemented for `memory`, `file`, `prisma`, and `drizzle`. `drizzle` additionally needs
  `ops.isNull` configured (matching `deletedAt` filtering) to match the global/unscoped
  case correctly; without it, `updateAssignmentScope` returns `false` and the engine falls
  back automatically. Not implemented for `redis` (scope is encoded into the Set member
  itself, so there's no cheaper path than remove + add) or `http` (would need a new
  endpoint on the operator's server) - both already work correctly via the fallback.

  `iamAssignments` gains `updatedAt`/`updatedBy` in the drizzle schema (pg/mysql/sqlite)
  to support this - the only table getting them in this release, since it's now the only
  one with a real update path that didn't already have them.

### Patch Changes

- 2853214: Round out audit columns on the drizzle schema (pg/mysql/sqlite): `iamPolicies` and
  `iamRoles` gain `deletedAt`; `iamSubjectAttrs` gains the `createdBy` it was missing
  (it already had `updatedBy`) plus `deletedAt`. `iamAssignments`' own audit columns
  are covered separately, alongside the new `updateAssignmentScope` feature that needs
  them.

  `IamDrizzleAdapter`'s `ops` config gains an optional `isNull` operator. When
  provided, `listPolicies`/`getPolicy`/`listRoles`/`getRole`/`getSubjectRoles`/
  `getSubjectScopedRoles`/`getSubjectAttributes` exclude rows with `deletedAt` set;
  omitted (the default, matching every version before this column existed), reads are
  unchanged. `deletePolicy`/`deleteRole`/`revokeRole` still hard-delete on purpose -
  turning them into soft-deletes would break the unique-name constraint on policies/
  roles (a "deleted" name couldn't be reused) and orphan the FK cascade from
  `iamAssignments`. The column is a hook for something outside the adapter to set
  (an admin tool, a trigger), not something this adapter writes itself.

- 2853214: Fix scoped role assignments not resolving inherited roles. `resolveSubject` closed
  `subject.roles` over `inherits` but passed `subject.scopedRoles` through unresolved,
  so a condition reading `subject.scopedRoles` saw only the directly assigned role and
  not what it inherits, while the exact same role assigned without a scope resolved
  correctly. Scoped roles now go through the same inheritance closure.

  `IamClient` also gains `PartialPermissionMap`, the type `engine.permissions()`
  actually returns (only the checked keys, not every possible combination). The React
  client's `usePermissions`/`createIamPermissionChecker`/`IContextValue.permissions`
  now use it instead of the full `PermissionMap`, matching what callers really have.
  `iamBuildPermissionKey` is also re-exported from the React entry so a consumer
  building a key by hand doesn't need a second import from core.

## 5.4.2

### Patch Changes

- 4d956c8: No functional change. Version bump to resync with the registry after 5.4.1 was
  published without its git history being committed.

## 5.4.1

### Patch Changes

- 959a8a4: Restructure the drizzle adapter's schema exports into per-dialect folders, matching
  `@gentleduck/auth`'s layout.

  `@gentleduck/iam/adapters/drizzle/schema/{pg,mysql,sqlite}` is now
  `@gentleduck/iam/adapters/drizzle/{pg,mysql,sqlite}`. Each folder also exports a
  `{Pg,Mysql,Sqlite}` types namespace (`PolicyRow`, `RoleRow`, `AssignmentRow`, `AttrRow`)
  inferred from that dialect's schema, so a consumer pinned to one dialect no longer needs
  to import the adapter's cross-dialect union types to get a concrete row shape.

  Update imports from `@gentleduck/iam/adapters/drizzle/schema/pg` (etc.) to
  `@gentleduck/iam/adapters/drizzle/pg` (etc.).

## 5.4.0

### Minor Changes

- 39aaa82: Export the factories, and finish the barrels.

  The previous release gave every publicly constructed class a factory function, but
  several were never exported, so `new` remained the only reachable spelling for
  `AnomalyFacet`, `HijackFacet`, `WebhookDeliverer`, `MemoryPasskeyChallengeStore`,
  `AuthMemoryDeviceFingerprintStore`, `DPoPVerifier`, the data-at-rest providers, the
  password hashers, and the api-key / magic-link / passkey / saml / passwords impls.

  The channels barrel exported one type and nothing else, so every channel had to be
  imported by deep path. All six ship from `@gentleduck/auth/channels` now. The anomaly
  barrel likewise omitted both detectors and the fingerprint store, which meant the
  detectors could not be registered without reaching past it.

  On the IAM side, `iamEngine` and `iamLRUCache` are exported alongside their classes.

  BREAKING: three aliases in the `@gentleduck/auth` root now name the factory rather than
  the class, so `new` on them stops compiling.

  - `AuthBackupCodesFacet` is now `backupCodesFacet`; the class is `BackupCodesFacet`.
  - `AuthInMemoryEvents` is now `inMemoryEvents`; the class is `InMemoryEvents`.

  Both classes are exported under their own names, so `new BackupCodesFacet(...)` and
  `new InMemoryEvents()` are the mechanical fix.

- 196f52d: Reject a policy whose target names a pair no allow rule covers, instead of warning.

  `UNREACHABLE_TARGET` was a warning, so `PolicyBuilder.build()` accepted the policy and
  the only symptom was a denial at request time. A denial reads as the permission system
  working, which is why this cost five separate incidents to recognise: widening a target
  is one line and widening the rules is another, nothing couples them, and the drift is
  silent.

  It is now an error, so `build()` throws where the policy is written.

  Two supporting fixes:

  - The check treated a dimension the target omits as a literal `*`, which demanded that
    every rule be a wildcard. A target naming only `impersonate` was reported unreachable
    because its allow rule named `.of('users')`. An omitted dimension is one the target
    does not constrain, so only the dimensions it names are checked.
  - `PolicyBuilder.build()` dropped the validator's message and reported only the code and
    path, so every build failure was cryptic. It now includes the message and the policy id.

  Also re-enables the two drizzle adapter suites, commented out wholesale in f3f57cb8
  "pending rename follow-up" that never landed. `IamDrizzle.IConfig` had gained
  `<TDb, TType>` in that rename and the suites still referenced it bare. 62 tests back,
  and they are not decorative: removing the JSONB shape guard, silencing `onPolicyError`,
  and dropping the WHERE from the single-row lookup are each caught.

  BREAKING: a policy with an unreachable target now throws at build time rather than
  loading with a silent denial.

### Patch Changes

- Make the not-blank check constraints reject whitespace.

  `length(trim(x)) > 0` only strips ordinary spaces, so a name, subject id, scope or
  credential secret consisting of a tab, a newline or a form feed passed the check that
  exists to refuse exactly that. Seven constraints were affected:
  `auth_credentials.secret`, `iam_assignments.subject_id` and `.scope`, `iam_policies.name`,
  `iam_roles.name` and `.scope`, `iam_subject_attrs.subject_id`.

  Each dialect gets the strongest form it has. Postgres and MySQL match a non-whitespace
  character (`~ '[^[:space:]]'` and `REGEXP '[^[:space:]]'`); SQLite has no regexp operator
  built in, so it trims the whitespace set explicitly and compares against the empty string.
  All three were verified against a real server for a tab, a newline, a carriage return, a
  vertical tab, a form feed and a plain space.

  Existing databases need a migration: drop each constraint and add it back in the new form.
  Any row already holding a whitespace-only value has to be repaired first, or the
  `ALTER TABLE` is refused.

- Close scoped role assignments over `inherits`, the way direct assignments already were.

  `resolveSubject` ran `resolveEffectiveRoles` over the roles returned by `getSubjectRoles`
  and passed `getSubjectScopedRoles` through untouched. A deployment that scopes every
  assignment therefore had an empty `subject.roles` and a flat scoped set, so a condition
  reading `subject.roles` saw the assigned role and none of the roles it inherits.

  The effect was silent and direction-dependent: RBAC permission resolution walks `inherits`
  separately, so a superadmin still had every permission its parents grant, while
  `w.role(...)`, `w.roles(...)` and `w.contains('subject.roles', ...)` behaved as if the
  hierarchy did not exist. The same policy then decided differently depending on whether the
  assignment carried a scope, which is not something the API hints at.

  Scoped roles now expand through the same closure, each inherited role keeping the scope of
  the assignment it came from.

## 5.3.0

### Minor Changes

- Warn when a policy target names an action/resource pair no rule can allow.

  `evaluatePolicy` folds `defaultEffect` when a policy's target matches and none of its
  rules do, and that default is `deny`. A target therefore widens what a policy refuses,
  not only what it inspects: adding a resource to `.target({ resources: [...] })` without
  an allow rule covering it denies every caller for that resource, and the refusal
  surfaces far from the policy that caused it.

  `validatePolicy` now emits an `UNREACHABLE_TARGET` warning per uncovered pair. It fires
  only once the policy contains at least one allow rule, so a purely restrictive policy -
  where denying everything the target names is the whole point - is untouched.

  Warning rather than error: the behaviour is correct deny-by-default and existing
  policies that rely on it keep validating.

## 5.2.0

### Minor Changes

- bc8a9ea: Prefix the drizzle tables and constraints with `iam_`, and let the Nest access
  guard contribute resource attributes.

  **Renamed tables and constraints.** The physical tables move from the
  `access_*` prefix to `iam_*` (`access_policies` → `iam_policies`,
  `access_roles` → `iam_roles`), along with every derived `pk_`, `uq_`, `idx_`
  and `ch_` identifier, in the `mysql`, `pg` and `sqlite` schema builders. This
  makes the schema attributable to this package once merged into a host
  application's database.

  Existing databases need a migration renaming those tables and their
  constraints. New installations are unaffected.

  **`getResourceAttributes` on `iamNestAccessGuard`.** An optional hook that
  computes the attributes attached to `resource.attributes` before
  `engine.can()` runs. It receives the resolved `{ action, resource }` alongside
  the request, because the correct attributes are resource-specific: a `users`
  row is its own subject, whereas an `iamAssignments` row carries its subject in
  a column. Passing the resolved pair means callers do not have to re-derive
  which case they are in from the raw request.

  **Known gap:** the drizzle adapter and native-attr-shape test suites (47 cases)
  are temporarily disabled while their mock table references are reworked for the
  rename.

## 5.1.0

### Minor Changes

- Restructure core into `engine/` and `config/` subfolders matching duck-iam patterns. Rename `defineAuth` → `createAuth` as primary entry point. Extract `AuthEngineTypes` and `AuthDefine` into dedicated types files. Add `Auth` prefix to all public classes.

## 5.0.1

### Patch Changes

- fix: strip redundant iam/auth prefixes from public exports

## 5.0.0

### Major Changes

- Prefix all public exports with package namespace (`Auth*`/`Iam*`/`IAM_*`/`AUTH_*`) so the origin is clear at the type level when both packages are imported together. This is a breaking change — all consumers must update import references to the new names.

  **It is not a pure prefix rename.** Most names took the prefix mechanically, but
  a few changed shape or went away, and those are the ones a find-and-replace
  upgrade walks into. Renames:

  | 4.x                      | 5.0.0                       | Subpath                           |
  | ------------------------ | --------------------------- | --------------------------------- |
  | `Engine`                 | `IamEngine`                 | `@gentleduck/iam`                 |
  | `MemoryAdapter`          | `IamMemoryAdapter`          | `/adapters/memory`                |
  | `DrizzleAdapter`         | `IamDrizzleAdapter`         | `/adapters/drizzle`               |
  | `PrismaAdapter`          | `IamPrismaAdapter`          | `/adapters/prisma`                |
  | `HttpAdapter`            | `IamHttpAdapter`            | `/adapters/http`                  |
  | `accessMiddleware`       | `iamAccessMiddleware`       | `/server/express`, `/server/hono` |
  | `guard`                  | `iamGuard`                  | `/server/express`, `/server/hono` |
  | `adminRouter`            | `iamAdminRouter`            | `/server/express`                 |
  | `withAccess`             | `withIamAccess`             | `/server/next`                    |
  | `checkAccess`            | `checkIamAccess`            | `/server/next`                    |
  | `getPermissions`         | `getIamPermissions`         | `/server/next`                    |
  | `createNextMiddleware`   | `createIamNextMiddleware`   | `/server/next`                    |
  | `nestAccessGuard`        | `iamNestAccessGuard`        | `/server/nest`                    |
  | `createEngineProvider`   | `createIamEngineProvider`   | `/server/nest`                    |
  | `generatePermissionMap`  | `generateIamPermissionMap`  | `/server/generic`                 |
  | `createAccessControl`    | `createIamAccessControl`    | `/client/react`                   |
  | `createVueAccess`        | `createIamVueAccess`        | `/client/vue`                     |
  | `createRedisInvalidator` | `createIamRedisInvalidator` | `/invalidators/redis`             |
  | `buildPermissionKey`     | `iamBuildPermissionKey`     | `@gentleduck/iam`                 |
  | `ACCESS_ENGINE_TOKEN`    | `IAM_ACCESS_ENGINE_TOKEN`   | `/server/nest`                    |
  | `ACCESS_INJECTION_KEY`   | `IAM_ACCESS_INJECTION_KEY`  | `/client/vue`                     |

  **Removed, not renamed** — these need a code change, not an import change:

  | 4.x                            | What to do instead                                                                                                                                                                                                     |
  | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | `createTypedAuthorize<A, R>()` | Use `IamAuthorize<A, R>(meta)` directly. It **is** the decorator; there is no factory to call first. Keep your call sites by aliasing: `const Authorize = (m: IamNest.IAuthorizeMeta<A, R>) => IamAuthorize<A, R>(m)`. |
  | `PermissionMap` (root)         | `IamClient.PermissionMap` / `IamClient.PartialPermissionMap`.                                                                                                                                                          |
  | `DefaultContext` (root)        | `DotPath.IDefaultContext`.                                                                                                                                                                                             |
  | `validateRoles` (root)         | Import from `@gentleduck/iam/core/validate` — it is deliberately off the root barrel so the 12 KB validator chunk stays lazy.                                                                                          |
  | `createAccessConfig`           | `createIam`.                                                                                                                                                                                                           |

  Scoped permission keys also changed format in this line: `scope:action:resource`
  became `@scope:action:resource`. A 3-part key without the `@` still parses — as
  `action:resource:resourceId` — so a stale key silently becomes a different
  question rather than an error. Regenerate hand-written maps with
  `iamBuildPermissionKey`.

## 4.0.0

### Major Changes

- a5fb285: Rename the policy builder factory to `definePolicy`, matching `defineRule` and
  `defineRole`.

  BREAKING: the `policy()` factory and `access.policy()` method are removed. Use
  `definePolicy()` and `access.definePolicy()` instead - the builder API is
  otherwise unchanged.

## 3.2.0

### Minor Changes

- f77fb5a: Harden and type the Drizzle adapter schemas (pg, mysql, sqlite).

  - Add `json: 'native' | 'string'` adapter option. `'native'` (default) writes plain objects to `jsonb`/`json` columns so payloads stay queryable; `'string'` JSON-stringifies for SQLite/text columns. The read path accepts both, so switching is migration-safe.
  - Type every JSON column with `$type<>()` against the `AccessControl` types; constrain `algorithm` with a Postgres enum, a MySQL enum, and a SQLite CHECK.
  - Add CHECK constraints (non-blank name/subject, `version >= 1`), `created_by` / `updated_by` audit columns, GIN indexes (pg), partial indexes for scoped rows (pg/sqlite), and a `roleId` index.
  - Collapse NULL scopes in unique constraints (`NULLS NOT DISTINCT` on pg, `COALESCE(scope, '')` on mysql/sqlite) so duplicate global rows are rejected.
  - Name every constraint (`pk_`, `fk_`, `uq_`, `idx_`, `ch_`).

  Fixes: pg `inherits` was `text[]` but the shared adapter writes JSON, so it is now `jsonb`; the MySQL timestamp default was a static import-time snapshot and is now per-row `CURRENT_TIMESTAMP(3)`.

  Migration note: regenerate migrations with `drizzle-kit generate`. SQLite users must pass `json: 'string'`.

## 3.1.0

### Minor Changes

- e5fc356: # @gentleduck/iam 3.1

  Engine structure cleanup + adapter validation hardening.

  ## New exports

  - **`parsePolicyRow` / `parseRoleRow`** from `@gentleduck/iam/core/validate`. Helpers for custom-adapter authors: take an `unknown` row, return the typed `AccessControl.IPolicy<...>` / `AccessControl.IRole<...>` when structurally valid, or `null` to drop the row. Replaces the pattern of calling `validatePolicy(row)` then casting `row as IPolicy<...>`.

  ## Internal refactors (no public API change)

  - `engine.ts` split into five single-purpose modules under `core/engine/`:
    - `engine.invalidation.ts` - cross-instance + in-flight cache invalidation
    - `engine.loaders.ts` - cache-fronted loaders with single-flight coalescing + adapter timeout + max-row guards
    - `engine.hooks.ts` - safe hook calls + metrics emission with throw-swallowing
    - `engine.lifecycle.ts` - preload / health-check / dispose
    - `engine.stats.ts` - snapshot / reset / hit-rate aggregation
  - File, Redis, Drizzle, and Prisma adapters now route every row-decode path through `parsePolicyRow` / `parseRoleRow` instead of bare `as` casts. Prisma's `listPolicies` / `getPolicy` / `listRoles` / `getRole` now actually validate before returning - this was a latent gap.
  - `core/explain` is now lazy-loaded by `engine.explain()` via dynamic `import()`. Production-mode bundles drop the explain chunk entirely.

  ## Tests

  - 50 new direct unit tests for the extracted engine helpers (invalidation, hooks, stats, lifecycle, loaders). The class-method shims are proved to delegate to the extracted free functions, not just rename.

  ## Documentation

  - `AUDIT-RESULTS.md` checked in. 0 runtime advisories.
  - The two reported workspace-level vulnerabilities affecting `@gentleduck/iam` are both in `role-acl` (a benchmark competitor in `devDependencies` only); never installed by consumers.

  ## Migration

  None required. All changes are additive or internal.

## 3.0.1

### Patch Changes

- 1f5ac74: **@gentleduck/auth**: end-to-end input + tenant + config-time hardening sweep.

  - Provider entry-point caps + typeof guards (api-key, magic-link, oauth, passkey, password, saml). Magic-link `callbackPath` validated at construction (refuses protocol-relative + CR/LF). OAuth `redirectUri` + endpoint URLs validated. SAML `relayState` + `host` CR/LF guard.
  - Facet input caps (flows, sessions, mfa, apikeys, identities, idempotency). `isProviderIdSafe` guard in `signIn` / `beginProvider`. CAS-claim on recovery + signup. Email canonicalization (`trim().toLowerCase()`) shared between rate-limit + lookup + stored metadata.
  - Transport hardening: 4 KB bearer cap, 8 KB DPoP cap, 16 KB cookie-header cap, cookie name RFC 6265 validation. JWT `signKey.kid` + `signKey.key` validation. `Number.isFinite` on iat / nonce / counter rollback. timingSafeEqual on `ath` + `nonce`.
  - Adapter parity: memory adapter `findByHashedSecret` respects `ctx.tenantId` (was searching globally) + uses `isRevoked` predicate. `upsert` inherits `tenantId` from ctx. Redis adapter caps key length + clamps NaN/huge ttl. SQL adapters parameterize JSONB queries.
  - `AuthRoot.strict`: refuse `http://` baseUrl in production.
  - Webhooks: `redirect: 'error'` SSRF, 1 MiB payload cap, 20-attempt backoff cap, NaN-timestamp rejection.
  - New `@gentleduck/auth/server/{fastify,koa,nestjs,elysia,grpc}` adapters.
  - New providers: SAML 2.0 SP, Microsoft, Discord, LinkedIn, Sign in with Apple, api-key sign-in.
  - New channels: Resend, Twilio, Web Push, AWS SES.
  - DPoP (RFC 9449) + OAuth refresh-reuse detection.
  - READMEs: parallel structure across both packages, local logo + LICENSE for npm rendering.

  **@gentleduck/iam**: defense-in-depth + adapter hardening + vitest compat shim.

  - `engine.libs.assertNonEmptyStringParam`: enforce 1024-char cap. `assertAttributesParam`: 256-key + depth-16 caps. `engine.permissions()`: refuse batches >1024. `engine.can()` / `check()` / `explain()`: subjectId typeof + length-cap; fail-closed in production.
  - File adapter dicts now `Object.create(null)` (prototype-pollution defense). `setSubjectAttributes('__proto__', ...)` no longer pollutes Object.prototype.
  - HTTP adapter: streaming `readBodyCapped` + `readJsonCapped<T>` so multi-GB remote bodies cannot OOM before slice. ID-length caps. Backoff overflow cap. SSRF `redirect: 'error'`.
  - Redis invalidator: pre-auth UTF-8 byte-length cap + depth/key-count cap on parsed envelopes.
  - Hono adapter: body Reflect.get-parsed with typeof + length guards.
  - Vitest compat shim for bun runtime (`stubGlobal` / `unstubAllGlobals` / `describe.runIf`); 8 previously-failing devtools tests now pass.

  **Tests**: +42 across both packages, all green. No functional behavior changes beyond defensive guards on hostile input.

## 3.0.0

### Breaking - Engine facet split

The flat cache + stats methods on `Engine` move onto two facets. The
evaluation surface (`authorize`, `can`, `check`, `explain`, `permissions`)
and lifecycle (`constructor`, `dispose`, `preload`, `healthCheck`) stay
flat - they are the hot path and benefit from a single noun.

#### Migration

| Before (<= 2.x)                        | After (3.0)                                |
| -------------------------------------- | ------------------------------------------ |
| `engine.invalidate(opts)`              | `engine.cache.invalidate(opts)`            |
| `engine.invalidateSubject(id, opts)`   | `engine.cache.invalidateSubject(id, opts)` |
| `engine.invalidatePolicies(opts)`      | `engine.cache.invalidatePolicies(opts)`    |
| `engine.invalidateRoles(id?, opts)`    | `engine.cache.invalidateRoles(id?, opts)`  |
| `engine.stats()`                       | `engine.stats.get()`                       |
| `engine.resetStats()`                  | `engine.stats.reset()`                     |
| `engine.flushSharedCaches()` (removed) | `import { flushSharedCaches } from ...`    |

Codemod is a five-line `sed`; no behavior change. Reason for cutting now
instead of waiting: bundling the deprecation with `flushSharedCaches`'s
already-scheduled 3.0 removal means one major version, one migration
window.

#### Why

`Engine` had 16 public methods on one class. Four cluster cleanly:
evaluation, cache invalidation, lifecycle, observability. Folding the
last two clusters into facets drops the flat surface to 9 methods + 2
facet handles, which reads cleaner and gives room for future facet
growth (e.g. `engine.cache.prewarm()`, `engine.stats.subscribe()`)
without polluting the root.

The `flushSharedCaches` instance method was misleading - it wiped
process-globals, so calling it on one engine affected every other engine
in the process. Removed; module-level export is the honest surface and
has been the documented one since 2.1.

## 2.2.0

### Architecture debt cleanup + bundle slim

Follow-up to the 2.1.0 security audit. Closes maintenance gaps the cycle
surfaced and trims the bundle so the "import everything" headline is no
longer the only number.

#### Architecture

- **`runSingleFlight` + `runSingleFlightKeyed`**: 5 copies of the sentinel-
  compare in-flight pattern in `engine.ts` (`_loadPolicies`, `_loadRoles`,
  `_loadRbacPolicy`, `_loadAllPolicies`, `_resolveSubject`) collapsed to one
  helper. Same-class bugs (a missed sentinel in the merger) are now
  structurally impossible.
- **`runAdminAuthz` + `withAdminAudit`**: extracted from the 4 server
  adapters (express / hono / nest / next). The csrf + authorize + try +
  audit shape lives in one place. Future changes land in one file instead
  of four.
- **Per-Engine evaluation caches**: `regex` and `path` caches threaded
  end-to-end through `evaluate / evaluateFast / evaluatePolicy /
evaluatePolicyFast / matchCandidate / ruleApplies / evalConditionGroup /
evalCondition / resolve`. Multi-tenant deployments instantiate one
  Engine per tenant; each owns its own caches and cannot be evicted by
  hostile-tenant pattern flooding. `flushSharedCaches()` remains for
  legacy callers.
- **Drizzle typed selects**: 7 `as unknown as` casts at module-edge
  consolidated into 3 typed helpers (`_selectAll`, `_selectFirst`,
  `_selectWhere`). Type system is load-bearing again.
- **Adapter compliance suite** at `src/adapters/__compliance__/`. Every
  shipped adapter passes the same 21 scenarios. Caught a `revokeRole`
  drift in `MemoryAdapter` and `FileAdapter` (omitting `scope` should
  remove all matching role rows, not just the unscoped one).
- **Builder auto-validate**: `PolicyBuilder.build()` and
  `RoleBuilder.build()` run `validatePolicy` / `validateRole` and throw on
  error. Power-users wiring the adapter directly (bypassing
  `engine.admin.savePolicy`) see failures where the bug was introduced.

#### Bundle slim

- **Lazy validator**: `engine.libs.ts` admin write paths
  (`savePolicy / saveRole / import`) now `await import('../validate')` on
  first call. The 12 KB validator chunk is skipped entirely by read-only
  services.
- **Subpath splits**: `@gentleduck/iam/core/validate`,
  `@gentleduck/iam/core/builder`, `@gentleduck/iam/core/explain`,
  `@gentleduck/iam/core/schema` each ship as separate entries.
  Tree-shaking drops them for consumers that don't import the subpath.
- **Barrel cleanup**: `src/index.ts` no longer re-exports `FileAdapter`,
  `MemoryAdapter`, or the validator. Adapter consumers go through subpath
  imports (`@gentleduck/iam/adapters/memory`).
- **Drop 26 `@deprecated` 2.0->3.0 type aliases**. `.d.ts` surface clean.
  The deprecation window from 2.0.0 is closed; consumers were warned for
  two minor versions.
- **Forensic comments scrubbed**: 452 redundant `@author` JSDoc tags and
  326 audit-trail reference comments removed from source.

#### New APIs

- **`flushSharedCaches`** module-level export (`@gentleduck/iam` and
  `@gentleduck/iam/core`). The instance method `Engine#flushSharedCaches`
  is deprecated - it wiped process-globals despite being instance-bound.
- **`engine.preload({ validator: true })`** eagerly loads the lazy
  validator chunk at boot for operators who want every cost up front.
- **`engine.permissions(..., { telemetry: false })`** opt-out of per-check
  `onMetrics` + `signals` allocation. Restores 2.0.x throughput on hot UI
  gates where `authorize()` already captures the metrics signal.
- **`escapeHtml`** from `@gentleduck/iam/core/explain`. Safe HTML escape
  for consumers rendering `Explain.IResult.summary` into a debug panel.
- **`createEvalCaches`** from `@gentleduck/iam/core` constructs a fresh
  per-Engine cache pair if a consumer needs to build their own evaluator
  pipeline.
- **`splitPermissionKey`** from `@gentleduck/iam/shared/keys` reverses
  `buildPermissionKey` honouring escape sequences.

#### Tests

- 836 -> **943** (+107). The +107 is the new adapter compliance matrix
  applied to 5 adapters.

#### Stryker mutation testing scaffold

`bun run mutation` wires Stryker against engine + evaluate + conditions +
resolve + validate + server/generic + all 5 adapters. Not in CI by default
(5-15 min runtime); operators run on demand or via scheduled job.

#### Benchmarks

Measured baselines (2.0.1 from `git worktree` clean build, not eyeballed):

| Path                          | 2.0.1       | 2.1.0    | 2.2.0        |
| ----------------------------- | ----------- | -------- | ------------ |
| `evaluatePolicy` (conditions) | 1.33 µs     | 1.00 µs  | 1.00 µs      |
| `engine.can()` cached         | 4.86 µs     | 5.85 µs  | 5.18 µs      |
| `engine.permissions()` x20    | 20.06 µs    | 42.71 µs | 48.08 µs     |
| Bundle "import everything"    | **38.4 KB** | 44.8 KB  | **41.3 KB**  |
| Bundle realistic profile      | n/a         | n/a      | **15-25 KB** |

Net 2.0.1 -> 2.2.0 bundle delta: **+2.9 KB (+7.5%)**. Earlier docs cited
a ~21 KB pre-cycle number - that was estimated from a partial dist, not
a clean build. The full security cycle cost ~6 KB raw; the bundle slim
cycle recovered ~3 KB; net is +2.9 KB for fail-closed hook contracts,
per-Engine caches, default-on CSRF, and lazy validator scaffolding.

`engine.permissions(..., { telemetry: false })` cuts the batch path back
to ~22 µs for callers who opt out.

`engine.permissions(..., { telemetry: false })` cuts the batch path back
to ~22 µs for callers who opt out.

## 2.1.0

### Adversarial security audit cycle

A second multi-round audit pass after 2.0.0. Spans **21 rescan cycles** across two adversarial security-auditor agents plus a silent-failure hunter and a code-smell scanner. Resulted in **~60 fix commits** addressing 1 CRITICAL, 7 HIGH, 11 Medium, 12 Low, and 4 Info findings on top of the 2.0.0 hardening. Three consecutive clean rescans (Med+ free) declared the source tree exhausted: _"the package is genuinely hard to break."_

The change set is **mostly backward compatible** with two notable defaults:

1. **Hono `accessMiddleware` + `guard` no longer default to `x-user-id` header**. Spoofable. Now reads only `c.get('userId')` populated by upstream auth. Operators relying on the header must wire `getUserId` explicitly.
2. **Next `withAccess` requires `getUserId`**. Previous default also trusted the header. Throws at construction when omitted.
3. **Admin routers CSRF-check by default** (CAVEAT-2). New `defaultCsrfCheck` rejects browser requests with `Sec-Fetch-Site: cross-site|cross-origin`. Bearer/mTLS APIs opt out via `csrfCheck: false`. Cookie-auth admin UIs get protection without any opt-in.

#### CRITICAL (1)

- `FileAdapter._loadState` swallowed every `readFile` error and silently fell back to an empty store. EACCES (permissions drift), EISDIR (path overwritten), EIO (disk corruption) became `{policies:{},roles:{},...}`. With `defaultEffect:'allow'+allowFailOpen` this is total silent fail-open; with `'deny'` it's total silent outage. Only `ENOENT` now recovers as empty; everything else throws a wrapped Error.

#### HIGH (8)

- HTTP adapter followed fetch redirects without re-validation. A 302 to `169.254.169.254` or `10.0.0.5:6379` bypassed the construction-time `allowedHosts` / private-IP guard. `_fetchOnce` now passes `redirect: 'error'`.
- `_emitMetrics` invoked `onMetrics` without a try/catch. A throwing operator hook escaped `authorize`'s catch arm and replaced the documented fail-closed deny with a raw error. Wrapped via `_safeHookCall`; double-wrapped around `console.error` itself.
- `afterEvaluate` / `onDeny` ran inside `authorize`'s main try block; throws caught by the evaluation catch silently rewrote an allow verdict into a fail-closed deny. Trailing hooks now run outside the evaluation try; throws routed to console.error without reshaping the decision.
- `engine.permissions()` passed `undefined` for `onPolicyError` to evaluator - per-policy throws vanished. UI gates silently allowed under `defaultEffect:'allow'`. Now forwards the same shim `authorize()` uses.
- Redis + Drizzle `getSubjectAttributes` returned `{}` on JSON.parse failure or non-object root. ABAC conditions silently flipped to deny. Now throws; engine routes through `onError` + fail-closed deny.
- `FileAdapter` JSON parse failure silently populated `_cache = {}`. Next `_flush()` overwrote the recoverable-but-corrupt file. **Permanent data destruction triggered by a single transient parse error.** Now throws "store corrupt - refusing to load; restore from backup before retrying".
- `can()` / `check()` invoked `this._hooks.onError?.()` unwrapped - /058 throws routed through these catches; a throwing operator `onError` propagated as unhandled rejection. Now `_safeHookCall`.
- Hono / Next default `getUserId` trusted spoofable `x-user-id` header. **Trivial auth bypass via curl.** Hono: no header fallback. Next: required option, throws on construction without it.

#### Medium (11)

- Admin write path skipped validation. Hostile admin (or buggy UI) could persist a policy that adapter read-side validator silently drops -> tenant ends up with zero policies -> `defaultEffect` decides every request. `createAdmin.savePolicy / saveRole / import` now call `validatePolicy / validateRole` and throw on error.
- `assertValidOrThrow` echoed attacker-controlled values (`Invalid algorithm "<value>"`). Operator who opted into `includeErrorMessage:true` + HTTP body echo got a probe oracle. Now emits `INVALID_ALGORITHM at "algorithm"` - structural codes only.
- Redis migration vs `revokeRole` race. `_migrateLegacyAssignment`'s SADD-then-SREM let migrator resurrect a just-revoked assignment. `_runSerialised` per-key chain orders writes; revoke now SREMs both encodings.
- File `_assertWithinRoot` ran once per adapter; attacker swapping the file for a symlink after first I/O steered subsequent writes. Drops latch; realpath re-checks every read/write.
- `_assertWithinRoot` outside the load try; rejected promise stuck forever in `_loadInFlight`. Restructure clears in-flight via finally on any throw.
- caused admin lockout: `setSubjectAttributes` called the getter first, getter now throws on corrupt existing data -> operator could not overwrite. Setter catches the throw, logs, treats existing as `{}`.
- HTTP adapter `getSubjectRoles` forwarded server response verbatim; other adapters enforce unscoped-only. JSDoc now documents operator's contract responsibility.
- Admin router shipped without CSRF guidance. Cookie-auth deployments exposed to cross-site forms. Optional `csrfCheck` added to all 4 framework adapters; default-on via `defaultCsrfCheck` (CAVEAT-2).
- `engine.permissions()` had no outer try around `Promise.all([_resolveSubject, _loadAllPolicies])`. Adapter rejection crashed the whole batch without `onError` + fail-closed map. Now wraps in try; returns all-deny map keyed by every requested check + invokes `onError`.
- `_loadAllPolicies` merger had no in-flight sentinel; concurrent invalidate-mid-load repopulated stale data. Added `_mergedInFlight` sentinel.
- `getSubjectRoles` semantic drift: file/memory returned unscoped-only; redis/drizzle/prisma returned all collapsed. Same subject resolved differently across backends. Aligned all to unscoped-only; documented in `Adapter.ISubjectStore`.

#### Low (15)

- No way to chart fail-open rate. Added `failOpen: boolean` to `IMetricsEvent` + counter to `createMetricsAggregator`. Threaded through `evaluate`/`evaluateFast` via optional `IEvalSignals`.
- Redis invalidator v:1 envelope was unwrapped without HMAC verification when `secret: null` - attacker chose `instanceId`, silenced legitimate cross-instance invalidates. v:1 in unsigned mode now dropped + warned.
- `permissions()` bypassed `_emitMetrics` entirely; dashboards charting fail-open missed every batch UI gate. Now emits per check.
- File `rootDir` warn fired every construction -> log spam -> operators filter the warning. Module-global latch fires once per process.
- File warn echoed resolved path -> path-existence oracle via log scraping. Path stripped from message.
- Redis invalidator one-shot per-channel warn latch let attacker burn the first warn on a benign reason then silently flood. Replaced with 60s rate-limit + suppressed-count surfacing.
- `errorToAuditString(includeMessage=true)` returned raw `String(err)` for non-Error throws - unbounded leak. Now tagged `<non-Error <typeof>>` + capped at 256 chars + `JSON.stringify` fallback.
- Devtools `localStorage` prefix `__IAM_DEVTOOLS` -> vendor-namespaced `__GENTLEDUCK_IAM_DEVTOOLS_V1`.
- `_assertWithinRoot` parent-realpath fallback fired on ANY error; ELOOP / EACCES bypassed symlink check via reconstructed path. Now gated on `code === 'ENOENT'`.
- Vanilla client listener-throw was totally silent. `console.error` surfacing.
- Invalidator dropped shape-mismatched inner payloads without `warnDropOnce` - operators saw nothing on sustained schema drift. Routed through warn.
- Invalidator `publish()` failure silently swallowed. Added optional `onPublishError(err, channel)` hook + rate-limited console fallback.
- `_safeHookCall` / `_emitMetrics` called `console.error` unwrapped; throwing logger (closed stdout, broken pipe) would resurrect . Defensive double-wrap.
- `dt/lib/flow.ts` listener `catch{}` silent. console.error added.
- Vanilla `extractAction` split key on `:` naively; resources containing `:` mis-tokenised. Added `splitPermissionKey` that honours `\\:`/`\\\\` escapes from `buildPermissionKey`.

#### Info (4)

- `createNextMiddleware` JSDoc example demonstrated the unsafe pattern. Replaced with `getServerSession` example + warning.
- Only express had a CSRF regression test; hono/next/nest needed parity. Added.
- **INFO-A** `LRUCache` + Engine `maxPolicies/maxRoles/adapterTimeoutMs` accepted NaN (silently disabled bound). Now `Number.isFinite` required.
- **INFO-B** `Explain.IResult.summary` is plain text with attacker-influenced values; consumers rendering as HTML must escape. JSDoc added.

#### Deployment hardening (CAVEAT-1/2/3)

- **CAVEAT-1**: `createRedisInvalidator({ tenantId })` auto-prefixes the channel `'duck-iam:invalidate:tenant:${tenantId}'`. Validates `tenantId` against `/^[A-Za-z0-9_-]{1,64}$/` so attacker-controlled tenant slugs cannot inject pub/sub wildcards.
- **CAVEAT-2**: Admin routers default-on CSRF via `defaultCsrfCheck` (Sec-Fetch-Site check). `csrfCheck: false` opts out for bearer/mTLS APIs.
- **CAVEAT-3**: `SECURITY.md` adds a 10-section **Deployment Hardening Guide** covering identity sourcing, admin CSRF, Redis tenancy, cache scoping, `defaultEffect:'allow'`, `explain()` output trust, adapter trust, file `rootDir`, HTTP `allowedHosts`, observability wiring.
- \*\*\*\*: `getCachedRegex` / `getSegments` accept optional per-instance cache override. `clearRegexCache()` / `clearPathCache()` exported. `Engine.flushSharedCaches()` ergonomic operator API for multi-tenant deployments.

#### New APIs (additive)

- `Engine.flushSharedCaches()` - wipe process-wide regex + path caches.
- `defaultCsrfCheck(req)` - exported from `server/generic`; built-in Sec-Fetch-Site predicate.
- `AdminAudit.IOptions.csrfCheck?: ((req) => boolean) | false`.
- `RedisInvalidator.IConfig.tenantId?: string`.
- `RedisInvalidator.IConfig.onPublishError?: (err, channel) => void`.
- `IMetricsEvent.failOpen: boolean`.
- `Metrics.ISnapshot.failOpen: number`.
- `splitPermissionKey(key)` - exported from `shared/keys`; escape-aware split.
- `clearRegexCache()` / `clearPathCache()` - process-wide cache flush.
- `Validate.ValidationCode` extended with `'ERR_REGEX_CATASTROPHIC'`.

#### Behaviour changes

- `adminRouter`/`bindAdminRouter`/`createAdminHandlers`/`createAdminOperations` enforce `defaultCsrfCheck` by default. Pass `csrfCheck: false` to restore old behaviour.
- Hono `accessMiddleware`/`guard` no longer fall back to `x-user-id` request header.
- Next `withAccess` requires `getUserId` (throws at construction).
- `FileAdapter.listPolicies/...` throws on non-ENOENT load failures (was silently empty).
- `FileAdapter` throws on malformed JSON (was silently empty + permanent file destruction on next flush).
- Redis/Drizzle `getSubjectAttributes` throws on corrupt blob (was `{}`).
- All 5 adapters' `getSubjectRoles` return unscoped-only (`getSubjectScopedRoles` still surfaces scoped separately).
- Engine ctor rejects NaN/Infinity for `maxPolicies`/`maxRoles`/`adapterTimeoutMs`.
- `LRUCache` ctor rejects NaN/Infinity for `maxSize`/`ttlMs`.

#### Tests

- 785 -> **836** tests (+51).
- 5 consecutive clean rescans (Med+ free): 010, 011, 012, 014, 017, 019, 020, 021 (intermediate Med+ found-and-fixed in 015, 018).

#### Audit hygiene

- `audit/` directory gitignored; per-finding markdown reports + per-cycle `rescan-NNN.md` reports tracked locally in `audit/STATE.md`.

## 2.0.1

### Patch Changes

- 41a45ac: Standardize README header to match the @duck-md template (centered logo, h1, tagline, nav, npm badges). Switch docs links from `iam.gentleduck.org` to path-based `gentleduck.org/duck-iam`. No runtime code changes.

## 2.0.0

### Breaking

- **Type API rewrite**: every interface now lives under a per-module namespace (`AccessControl`, `Request`, `Adapter`, `Primitives`, `Client`, `DotPath`, `EngineTypes`, `Evaluate`, `Explain`, `Validate`, `Config`, `Memory`, `File`) with an `I` prefix. Migration: rename `Policy` -> `AccessControl.IPolicy`, `Decision` -> `AccessControl.IDecision`, `AccessRequest` -> `Request.IAccessRequest`, etc.
- **`Adapter.IAdapter` read methods accept an optional `IReadOptions`** with an `AbortSignal`. Backwards-compatible for adapters that ignore the parameter; custom adapters should plumb the signal through to their underlying driver where possible.
- **`adminRouter` (Express) signature changed**: now requires `{ authorize: (req) => boolean }` as the second argument. Mounting unguarded admin endpoints used to be possible; it is no longer.

### Added

- **`policyCombine` cross-policy combine** (`'and'` / `'allow-overrides'` / `'first-applicable'`) configurable via `IConfig.policyCombine`.
- **`hooks.onMetrics`** primitive-only telemetry event fired once per evaluation in both modes.
- **`hooks.onPolicyError`** routed when a single policy throws during evaluation (fail-skip, not fail-crash).
- **`engine.preload()`** warms `mergedPolicyCache` so the first request after boot is hot.
- **`engine.healthCheck()`** returns `{ ok, adapter, cacheHitRate, adapterLatencyMs, lastError? }`.
- **`engine.admin.export()` / `engine.admin.import(snapshot, { mode })`** - schema-versioned policy + role snapshots; `'merge'` and `'replace'` modes.
- **`engine.dispose()`** releases the cross-instance invalidator subscription.
- **`IConfig.adapterTimeoutMs`** (default 5 s) wraps every adapter read in a timeout that triggers `AbortController.abort()`.
- **`IConfig.maxPolicies` / `maxRoles`** load-time caps; over-cap throws and routes to fail-closed deny.
- **`IConfig.allowFailOpen`** required to combine `mode: 'production'` with `defaultEffect: 'allow'`.
- **`IConfig.invalidator`** - cross-instance cache-invalidation broadcaster contract.
- **`createRedisInvalidator`** at `@gentleduck/iam/invalidators/redis` - pub/sub helper with self-echo filtering.
- **`createMetricsAggregator`** at `@gentleduck/iam/observability/metrics` - p50/p95/p99 over `onMetrics` events.
- **Hono `bindAdminRouter`**, **Next.js `createAdminHandlers`**, **NestJS `createAdminOperations`** - all require the `authorize` callback at construction time.
- **HttpAdapter** retry + per-request timeout + circuit-breaker (`retries`, `backoffMs`, `timeoutMs`, `circuitBreakerThreshold`, `circuitBreakerCooldownMs`).
- **FileAdapter** at `@gentleduck/iam/adapters/file` - JSON-on-disk store with pluggable `File.IFS` interface.
- **`POLICY_JSON_SCHEMA`** - Draft 2020-12 JSON schema export.
- **`engine.stats()` / `resetStats()`** - cache hit/miss counters per cache.

### Fixed

- `first-match` combiner now honors `rule.priority` across trace, fast, precomputed, and explain paths.
- `engine.explain()` populates `Decision.rule` from the deciding policy's trace.
- `engine.invalidateRoles(roleId?)` is scoped - only subjects holding the named role are evicted.
- `setSubjectAttributes` documented contract is now `merge`, matching every built-in adapter.
- Single-flight on `loadPolicies` / `loadRoles` / `resolveSubject` / `loadRbacPolicy` coalesces concurrent cold-start adapter calls. Sentinel-compare-on-resolve so a pending load can't write stale data after an invalidate.
- **NotApplicable semantics**: a policy whose `targets` don't match is skipped by the cross-policy combine, not folded as the default effect.
- Empty RBAC policy is skipped from the per-request policy set.
- Fast path matches colon-prefix actions (`'posts:*'`), dot-hierarchy resources (`'dashboard.*'`), and parent-prefix patterns.
- `evaluatePolicyFast` returns `boolean | null` (null = NotApplicable). `evaluateFast` skips null in every combine mode.
- Engine ctor refuses `mode: 'production'` + `policyCombine: 'first-applicable'`.
- RBAC rule ids are opaque (`__rbac__#N`) - no longer dotted.
- `matches` operator refuses `$`-resolved RHS values (ReDoS via user-controlled regex).
- HttpAdapter `getPolicy` / `getRole` return `null` on 404 instead of throwing.
- Validator depth bound (`MAX_CONDITION_DEPTH=10`) and field-length cap (`MAX_FIELD_LENGTH=256`).
- Regex cache is LRU on hit, not FIFO on insert.
- Synthesised RBAC policy is deep-frozen (every rule + conditions tree).
- `Number.isFinite` priority check in validator.

### Tests

- 629 tests across 29 files (up from 309 at 1.7.0).
- Property-based oracle asserts `evaluate == evaluateFast` over 1000 random policy sets per `(combine, defaultEffect)` pair.
- Bench harness: `evaluate.bench.ts` + `resolve.bench.ts` + competitor benchmarks.

### Dot-path attribute access (`When` builder)

The `When.attr()` / `When.resourceAttr()` / `When.env()` methods now accept dot-paths into nested attribute bags. Previously `resourceAttr` and `env` required `keyof` on the raw object shape (one level deep). Now `'profile.tier'` typechecks against `{ profile: { tier: string } }` and the value parameter narrows correctly.

New + reorganized in `DotPath`:

- **`SubjectAttrShape<TContext>`** - raw subject attribute bag object.
- **`ResourceAttrShape<TContext>`** - raw resource attribute bag object.
- **`EnvAttrShape<TContext>`** - raw environment object.
- **`SubjectAttrs<TContext>` / `ResourceAttrs<TContext>` / `EnvAttrs<TContext>`** - now return dot-path string unions (consistent), not raw objects.
- **`AttrValueAt<T, P>`** - walks a dot-path inside an attribute bag to resolve the leaf type.
- **`AttrValue<T, P>`** - rewritten on top of `AttrValueAt`, with `AttributeValue` fallback.
- **`ResolvedResourceAttrPaths<TContext, TResource>`** - dot-paths into per-resource attribute narrowing.
- **`ResolvedResourceAttrs`** - now returns the resolved attribute SHAPE (object), paired with `ResolvedResourceAttrPaths` for keys.

`When` method signatures dropped `keyof` in favour of these dot-path types. Open attribute bags (`IAnyAttributes` via `string` index signature) widen to `string` so the legacy `keyof IAnyAttributes` behaviour is preserved for `IDefaultContext`. File reorganized into 8 labeled sections (context paths, condition adapters, shape extractors, attribute paths, per-resource narrowing, value resolution, defaults, internal helpers).

### Module-local namespaces (added 2.0)

Every bare integration-config interface is now wrapped in a type-only namespace; deprecated bare aliases are kept for back-compat and will be removed in `3.0`.

- `Http.IConfig` (was `IHttpAdapterConfig`) - `@gentleduck/iam/adapters/http`
- `Redis.ILike` + `Redis.IConfig` (was `RedisLike` / `RedisAdapterConfig`) - `@gentleduck/iam/adapters/redis`
- `Drizzle.IConfig` (was `IDrizzleConfig`) - `@gentleduck/iam/adapters/drizzle`
- `Express.IOptions` + `Express.IAdminAuthorize` + `Express.IAdminRouterOptions` (were `IExpressOptions` / `IAdminAuthorize` / `IAdminRouterOptions`) - `@gentleduck/iam/server/express`
- `Hono.IOptions` + `Hono.IAdminAuthorize` + `Hono.IAdminOptions` + `Hono.IRouterLike` (were `IHonoOptions` / `IHonoAdminAuthorize` / `IHonoAdminOptions` / `IHonoRouterLike`) - `@gentleduck/iam/server/hono`
- `Nest.IAuthorizeMeta` + `Nest.IGuardOptions` + `Nest.IAdminAuthorize` + `Nest.IAdminOptions` (were `IAuthorizeMeta` / `INestGuardOptions` / `INestAdminAuthorize` / `INestAdminOptions`) - `@gentleduck/iam/server/nest`
- `Next.IWithAccessOptions` + `Next.IMiddlewareOptions` + `Next.IAdminAuthorize` + `Next.IAdminOptions` (were `IWithAccessOptions` / `INextMiddlewareOptions` / `INextAdminAuthorize` / `INextAdminOptions`) - `@gentleduck/iam/server/next`
- `ReactClient.IContextValue` (was `IContextValue`) - `@gentleduck/iam/client/react`
- `RedisInvalidator.IPubSubLike` + `RedisInvalidator.IConfig` (were `IRedisPubSubLike` / `IRedisInvalidatorConfig`) - `@gentleduck/iam/invalidators/redis`
- `Metrics.IAggregator` + `Metrics.ISnapshot` + `Metrics.IConfig` (were `IMetricsAggregator` / `IMetricsSnapshot` / `IMetricsAggregatorConfig`) - `@gentleduck/iam/observability/metrics`
- `AccessControl.OpFn` (was bare `OpFn` in `conditions.libs.ts`)

Every new namespace is **type-only** (interfaces + type aliases only, no runtime values) so it compiles to nothing and bundle size stays unchanged. Runtime helpers (`evaluatePolicyFast`, `ops`, `regexCache`, `MAX_*`, `POLICY_*`, every adapter class, every server factory, every client factory) remain bare module exports so tree-shaking still works.

### Stability

`2.0.0` commits to SemVer. The type-API namespace rewrite is load-bearing; no further public-API renames until `3.0.0`. Patch + minor releases stay non-breaking.

## 2.0.0 - detailed notes

### Major refactor: namespaced type API + correctness hardening

> These are the working notes for the 2.0.0 release above. They were written
> before the version was cut and kept their `Unreleased` heading afterwards,
> which put an "unreleased" section in the middle of shipped history. Retitled;
> content is unchanged.

13-round audit-driven hardening pass plus a full type-API refactor matching the duck-\* monorepo convention.

**Type API: namespaced + I-prefixed.** Every interface now lives under a per-module namespace (`AccessControl`, `Request`, `Adapter`, `Primitives`, `Client`, `DotPath`, `EngineTypes`, `Evaluate`, `Explain`, `Validate`, `Config`, `Memory`, `File`). Interface names carry an `I` prefix; type aliases stay bare.

**Engine correctness fixes:**

- `first-match` combiner now honors `rule.priority` across trace, fast, precomputed, and explain paths.
- `engine.explain()` populates `Decision.rule` from the deciding policy's trace.
- `engine.invalidateRoles(roleId?)` is scoped - only subjects holding the named role are evicted.
- `setSubjectAttributes` contract is now `merge`, matching every built-in adapter.
- Single-flight on `loadPolicies` / `loadRoles` / `resolveSubject` coalesces concurrent cold-start adapter calls.
- `invalidate()` family clears in-flight slots + sentinel-compare-on-resolve so a pending load can't write stale data.
- **NotApplicable semantics**: a policy whose `targets` don't match is skipped by the cross-policy combine, not folded as the default effect. Largest correctness fix in the project's history.
- Empty RBAC policy is skipped from the per-request policy set so it doesn't contribute a default-deny under AND combine.
- Fast path matches colon-prefix actions (`'posts:*'`), dot-hierarchy resources (`'dashboard.*'`), and parent-prefix patterns (`'org'` matching `'org:project'`) consistently with the trace path.
- `evaluatePolicyFast` returns `boolean | null` (null = NotApplicable). `evaluateFast` skips null in every combine mode.
- Engine ctor refuses `mode: 'production'` + `policyCombine: 'first-applicable'`.
- RBAC rule ids are opaque (`__rbac__#N`) - no longer dotted.

**New APIs:**

- **`AccessControl.PolicyCombine`** - cross-policy combine strategy (`'and'` / `'allow-overrides'` / `'first-applicable'`). Configurable via `Engine.policyCombine`.
- **`EngineTypes.IMetricsEvent` + `onMetrics` hook** - primitive-only telemetry payload fired once per evaluation in both dev and prod modes. Zero overhead when unwired.
- **`FileAdapter`** at `@gentleduck/iam/adapters/file` - JSON-on-disk store with pluggable `File.IFS` interface.
- **`POLICY_JSON_SCHEMA`** - Draft 2020-12 JSON schema export for non-TS consumers and editor tooling.
- **`Engine.stats()` / `resetStats()`** - cache hit/miss counters per cache.
- **Validator semantic checks** - emits `UNRESOLVABLE_FIELD`, `UNRESOLVABLE_VALUE`, `INHERITANCE_TOO_DEEP`, `BROAD_ALLOW`, `LIMIT_EXCEEDED` codes.
- **`POLICY_LIMITS`** - DoS bounds (1000 rules/policy, 100 actions/rule, 100 resources/rule, 1000 actionxresource cartesian/rule).
- **`MAX_INHERITANCE_DEPTH = 32`** exported from `core/rbac`. Validator errors on chains that exceed it.

**Build / package:**

- `sideEffects: false` in `package.json` for tree-shaking.
- `./adapters/file` subpath export added.

**Testing:**

- 584 tests across 28 files (up from 309 at 1.7.0).
- Property-based oracle asserts `evaluate == evaluateFast` over 1000 random policy sets per `(combine, defaultEffect)` pair.
- Bench harness: `evaluate.bench.ts` + `resolve.bench.ts` + competitor benchmarks.

## 1.7.0

### Minor Changes

- 0e80f84: Add Redis adapter, Drizzle schemas, and full integration test coverage.

  **New: `RedisAdapter`** at `@gentleduck/iam/adapters/redis`. Distributed key/value backend with idempotent `assignRole` (set semantics), multi-tenant `keyPrefix`, and a minimal `RedisLike` interface that ioredis, node-redis v4+, and Upstash all satisfy directly.

  **New: pre-built Drizzle schemas** at `@gentleduck/iam/adapters/drizzle/schema/{pg,mysql,sqlite}`. Drop-in tables for all three SQL dialects with the right column types, FK cascade on `roleId`, unique index on `(subjectId, roleId, scope)`, and auto-managed `created_at`/`updated_at`. Generate migrations via `drizzle-kit generate`.

  **Test coverage expansion**: every adapter, server middleware, and client integration now has dedicated tests. Total test count went from 309 to 498. New test files:

- `adapters/prisma`, `adapters/drizzle`, `adapters/http`, `adapters/redis`
- `server/express`, `server/hono`, `server/nest`, `server/next`
- `client/react`, `client/vue`

**Optional peer deps added**: `drizzle-orm`, `ioredis`, `redis` (all optional).

## 1.6.2

### Patch Changes

- 918b34c: Strip `workspace:*` and `catalog:` protocol tokens from `devDependencies`/`dependencies`/`peerDependencies` of every public package before `changeset publish`. Previously published artifacts leaked these tokens into npm metadata, which broke strict resolvers (bun, deno) for downstream consumers. Adds `scripts/clean-publish.ts` and wires it into the root `release` script with a `git checkout` restore step so source remains workspace-friendly.

## 1.6.1

### Patch Changes

- Add package README for npm page. Remove special characters from all documentation.

## 1.6.0

### Minor Changes

- Performance: evaluatePolicyFast now 2x vs CASL (was 5.2x). Inlined hot path, added pre-computed results cache for unconditional rules, fixed empty conditions bug, added combined action+resource index.

## 1.5.0

### Minor Changes

- e682b61: Add optional scope parameter to grant() for permission-level scoping

The `grant()` method now accepts an optional third `scope` argument:
`.grant('update', 'post', 'org-1')`. This enables permission-level
scoping directly without needing `grantScoped()`. The existing
`grantScoped(scope, action, resource)` method remains available.

Also fixed incorrect `first-applicable` references in JSDoc comments
to use the correct algorithm names `first-match` and `highest-priority`.

## 1.4.0

### Minor Changes

- 72c449b: Add FlexibleDollarPaths for $-value autocomplete and fix AttrValue for optional properties

- FlexibleDollarPaths<TContext> added directly to method value signatures so the IDE shows $-prefixed autocomplete (e.g. $subject.id) even without a custom context
- AttrValue now strips undefined from optional properties - yearsExperience?: number correctly resolves to number instead of falling back to AttributeValue
- StringConditionValue no longer includes (string & {}) internally - the flexible string fallback is handled at the method signature level via FlexibleDollarPaths

## 1.3.2

### Patch Changes

- 2dd9f8b: feat: FlexibleDotPaths for DefaultContext autocomplete and strict ConditionValue type safety

- DotPaths now bails to `never` (not `string`) for string-indexed types, preventing
  union pollution that killed IDE autocomplete.
- New FlexibleDotPaths<T> detects open-ended attribute bags (like DefaultContext) and
  adds `(string & {})` so known structural paths autocomplete while arbitrary strings
  are still accepted. Fully typed contexts remain strict.
- ConditionValue correctly restricts non-string value types: `env('hour', 'lt', '')`
  now errors when `hour` is `number`, instead of accepting any AttributeValue.

## 1.3.1

### Patch Changes

- b62bb5b: fix: prevent DotPaths from recursing into array methods and functions

DotPaths now treats arrays as leaf paths and skips function-valued properties,
so autocomplete only shows real data properties instead of array methods like
`length`, `push`, `toString`, etc.

## 1.3.0

### Minor Changes

- Add DollarPaths type for $-variable autocomplete in conditions, refactor core into modular folders, and add JSDoc and inline FAQs to documentation

## 1.2.0

### Minor Changes

- 7fe860f: Add TContext type parameter for typed dot-path intellisense and per-resource attribute narrowing. Split types.ts into modular types/ directory. Add JSDoc across all source files.

## 1.1.2

### Patch Changes

- 66608fe: Add publishConfig with public access for scoped npm package.

## 1.1.1

### Patch Changes

- 37339e8: Fix release workflow to skip redundant CI checks during publish.

## 1.1.0

### Minor Changes

- 29ed55d: Initial release of @gentleduck/iam - identity and access management utilities.
