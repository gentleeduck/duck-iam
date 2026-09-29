# duck-iam examples — build checklist

## Shared package (`examples/duck-iam/shared`)

- [x] `schema.ts` — `pgTable`s for companies/users/products/orders + re-export of the iam
      adapter's pg tables (`iamAssignments`, `iamPolicies`, `iamRoles`, `iamSubjectAttrs`,
      `combineAlgorithm`). `combineAlgorithm` has to be re-exported too, not just the tables —
      `drizzle-kit generate` only emits `CREATE TYPE` for an enum it finds as a top-level export
      of the schema file it reads, not one merely referenced by a column.
- [x] `iam.ts` — `createIam` schema, roles, `deny-self-account-delete` policy,
      `ANONYMOUS_SUBJECT_ID`, `buildEngine(db: AppDb)`. `AppDb` is `NodePgDatabase<typeof schema>`;
      the adapter takes no `dialect`/`json` overrides since `'pg'`/`'native'` are the defaults.
- [x] `seed.ts` — `seedDb(db)`, deterministic seed data (2 companies, 5 users across 4 roles,
      1 product + 1 order), cast-free (`buildEngine`'s typed `AppDb` param is enough).
- [x] `body.ts` — `readString`/`readNumber` JSON body helpers.
- [x] `db.ts` — `createDb(connectionString?)`, a `pg.Pool` + `drizzle-orm/node-postgres` factory.
      Default connection string points at the shared `duckiam_examples` database.
- [x] `drizzle.config.ts` / `drizzle/` — `dialect: 'postgresql'`, migrations generated once here,
      applied by every framework's `db:migrate` against the shared database.
- [x] verify: `bunx tsc --noEmit` clean, `drizzle-kit generate` emits the enum + all 8 tables.

## Per framework (Express / Hono / NestJS / Next.js)

Each directory is backend-only — `src/`, no nested `backend/` subfolder — and imports schema,
iam config, seed logic, and body helpers from `@examples/duck-iam-shared/*` rather than
redefining them locally. What's left per framework is genuinely per-framework: routing/
controllers, the `@gentleduck/iam/server/*` adapter wiring, and its own `pg.Pool` (a live pool
object can't cross an OS-process boundary, so `db/index.ts` calls `createDb()` itself — every
framework's pool still points at the same database).

- [x] `src/db/index.ts` — `export const { pool, db } = createDb()`
- [x] `src/db/migrate.ts` — `drizzle-orm/node-postgres/migrator`, `migrationsFolder` resolved to
      `../../shared/drizzle` (or `process.cwd()`-relative for Next, run via `tsx`), `pool.end()`
      after migrating so the one-off script actually exits.
- [x] `src/db/seed.ts` — `seedDb(db)` then `pool.end()`.
- [x] routes/controllers wired with the framework's adapter, `/me/permissions` batch endpoint
- [x] `package.json` — `@examples/duck-iam-shared` + `pg`/`@types/pg`; no `drizzle-kit`/
      `db:generate` (schema lives only in `shared/`)
- [x] verify: `bunx tsc --noEmit` clean, `bunx biome check` clean, boots, login + `/me/permissions`
      + tenant-scoped list + `deny-self-account-delete` (self-delete → 403) all confirmed via curl

NestJS keeps its `src/iam/iam.module.ts` as a thin re-exporting wrapper around
`@examples/duck-iam-shared/iam` (rather than every controller importing straight from `shared`)
specifically so `iam.guard.ts` and the controllers didn't need their import paths touched. This
also structurally removed the historical `iam.module.ts` → `iam.guard.ts` → `session.ts` →
`iam.module.ts` circular-import risk: `iam.module.ts` no longer imports domain logic from a
sibling file, so `ANONYMOUS_SUBJECT_ID` could move back into the shared `iam.ts` like every other
framework, instead of living in `session.ts` as a cycle-breaker.

**Bug referenced in code comments (`// see the Express example's TODO.md`, in every framework's
`POST /users/:id/role` handler):** `engine.admin.assignRole` alone is additive RBAC — a subject
can hold several roles per scope at once — but DuckMarket's domain model is "one company role per
user". Promoting `viewer` to `staff` then reverting `staff` to `viewer` without first revoking the
prior role left the user holding both, so the "revert" silently no-op'd (`create:products` stayed
granted). Every framework's role-assignment handler now revokes every other role the target holds
in that scope before assigning the new one.

Next.js keeps a local `src/iam/iam.ts` too — a thin wrapper that calls
`buildSharedEngine(db)` and adds the per-process `getEngine()` memoization Next's hot-reloading
dev server needs (a module-level `buildEngine()` call would otherwise open a fresh cached engine,
and a fresh pool, per request in some configurations).

## Migration to Postgres (from per-framework SQLite)

Originally each framework ran its own local SQLite file (`data.db`, via `bun:sqlite` on
Express/Hono/Nest and `better-sqlite3` on Next, which needed a different driver because
Turbopack's workers run under plain Node where `bun:sqlite` is unavailable). Moved to Postgres
so all four examples share one live dataset instead of four independent files:

- One new database, `duckiam_examples`, created on the existing `iryss-postgres` docker
  container — the same Postgres instance iryss's own dev stack runs, in its own database, not
  mixed into `iryss_marketplace`.
- `schema.ts` rewritten from `drizzle-orm/sqlite-core` to `drizzle-orm/pg-core`; iam tables now
  imported from `@gentleduck/iam/adapters/drizzle/pg` instead of `.../sqlite`.
- `IamDrizzleAdapter`'s `TType` parameter switched from `'sqlite'` to `'pg'` (and the sqlite-only
  `json: 'string'` option dropped — Postgres uses native `jsonb`).
- Connection driver unified across all four frameworks: `pg.Pool` + `drizzle-orm/node-postgres`
  everywhere, via the new shared `createDb()` factory. This also *removed* the
  Next-specific `better-sqlite3` special case entirely — `pg` is a pure JS/TS driver with no
  native-addon relocation problem under Turbopack, so Next now uses the exact same connection
  code as the other three.
- `next.config.ts`'s `transpilePackages` gained `@examples/duck-iam-shared` (it ships raw `.ts`
  like `@gentleduck/iam` already did).
- Migrations regenerated from scratch against the pg schema (old sqlite `drizzle/` + `data.db*`
  files deleted everywhere).

## Client removal

The earlier shared React client at `examples/duck-iam/client` (TanStack Start, talking to
whichever backend was picked at runtime) was deleted outright — these examples exist to show
`@gentleduck/iam`'s own server *and* client adapters used well inside each framework, not to add
a fifth app on top of four backends. Next.js's `src/app/dashboard` (using
`@gentleduck/iam/client/react`) is the one place a client adapter gets exercised, because
Next.js is the one framework where that's actually in-repo, not bolted on.

## Cleanup pass (env values + comment bloat)

- [x] `DATABASE_URL` is required everywhere it's read (`shared/src/db.ts`,
      `shared/drizzle.config.ts`) — no hardcoded connection string as a fallback, so a missing
      `.env` fails immediately instead of silently pointing at a default host.
- [x] Every package (`shared`/`express`/`hono`/`nest`/`next`) got its own gitignored `.env`,
      seeded from a checked-in `.env.example`. `next`'s `db:migrate`/`db:seed` scripts now run via
      `tsx --env-file=.env`, since `tsx` (unlike `bun` and `next dev`) doesn't load `.env` on its
      own.
- [x] Stripped multi-paragraph rationale comments (the AI-generated-looking kind) down to at most
      one line per note, across all five packages — the tenant-filter reasoning, the
      deny-self-account-delete `policyCombine` trap, the additive-RBAC role-revert workaround, the
      `asHandler`/`sessionOf` runtime-narrowing notes. Also fixed two comments left stale by the
      earlier Postgres pivot (`next/src/access.ts` and `next/src/iam/iam.ts` still said
      `bun:sqlite`) and removed a `biome-ignore` in `nest/src/session/session.ts` that biome
      reported as a no-op suppression.
- [x] `shared/src/body.ts`'s `fieldOf` no longer casts (`as Record<string, unknown>`) — replaced
      with a `hasKey` type-predicate so the narrowing is a real guard, not an assertion.
- [x] Re-verified for real, not just via typecheck: dropped and recreated `duckiam_examples`,
      re-ran `db:setup` from `express` and `db:migrate` from `next` off `.env` alone (no
      hardcoded fallback to fall back on), booted all four servers, logged in as
      `admin@acme.test` on all four ports (identical `userId`/`companyId` back), and hit a real
      `DELETE /users/user-admin-acme` against the live Postgres-backed engine — 403, same as
      before the cleanup.

## Verification (this round)

- `bun install` clean (root `workspaces.packages` collapsed the old
  `examples/duck-iam/*/backend` / `.../client` / `.../next` entries into one
  `examples/duck-iam/*` glob).
- `bunx tsc --noEmit` clean in `shared/`, `express/`, `hono/`, `nest/`, `next/`.
- `bunx biome check` clean (2 pre-existing `noNamespace` suppression warnings in
  `express/src/session.ts` and `nest/src/session/session.ts`, unrelated to this round).
- Fresh migrate + seed against `duckiam_examples`.
- All four servers booted simultaneously; confirmed identical `createdAt` timestamps back from
  `GET /users` on every port — proof it's the same physical rows, not four separate seeds — plus
  a matching `/me/permissions` grant map and a `deny-self-account-delete` 403 on Express.

## Real auth (duck-auth password + cookie sessions)

Replaced the fake `POST /session { email }` bearer-token stub across all four backends with real
`@gentleduck/auth` authentication — password credentials, cookie sessions, CSRF-guarded
mutations — mirroring how `examples/duck-auth` wires the same package. Built a real signup/signin
UI in the Next.js app; Express/Hono/NestJS stay API-only, curl-documented.

- [x] `shared/src/schema.ts` — `users.id` changed from `text` to `uuid`, a real FK into
      `authIdentities.id` (re-exported from `@gentleduck/auth/adapters/drizzle/pg`, alongside the
      iam tables, so `drizzle-kit generate` still emits everything from one file).
      `products.ownerId`/`orders.ownerId` (which reference `users.id`) changed the same way.
      `users.email`/`users.name` stay denormalized text columns.
- [x] `shared/src/auth.ts` (new) — `buildAuth(db)`: `drizzlePgAdapter(db)` stores, a
      `MemoryLimiter`, a `cookieTransport({ name: 'duckiam-sid', secure: false })`, and
      `passwords()` as the only provider. `resolveIdentityId(auth, headers)` is the one call every
      framework's session code makes.
- [x] `shared/src/seed.ts` — rewritten from id-keyed `onConflictDoNothing` to email-keyed
      idempotency (`auth.identities.getByEmail(email).orNull() ?? create(...)`), matching
      duck-auth's own seed pattern. All 5 demo accounts share password `duckiam-examples`
      (`DEMO_PASSWORD`, exported from `seed.ts`).
- [x] `shared/drizzle/` regenerated from scratch (old single migration deleted, `duckiam_examples`
      dropped/recreated) — 12 tables total: the 4 auth tables, 4 iam tables, 4 domain tables.
- [x] **Express** — `src/auth.ts` (`buildAuth(db)`), `src/routes/auth.ts`
      (`router.use(expressCsrf(auth))`, then the app's own signin/signout/session over
      `shared/src/routes.ts` and `/signup`), `src/session.ts` rewritten off `resolveIdentityId` + `toHeaders`. Every mutating
      domain router (`companies`/`users`/`products`/`orders`) takes `auth` and runs
      `router.use(expressCsrf(auth))` as its first line.
- [x] **Hono** — same shape via `shared/src/routes.ts` + `executeIntents`, CSRF applied
      as `router.use((c, next) => honoCsrf(auth)(toHonoAdapterCtx(c), next))`.
- [x] **NestJS** — split-controller idiom copied from `examples/duck-auth/nest`:
      `AuthController` (`@Controller('auth')`: signin/signout/session over `shared/src/routes.ts`) +
      `SignupController` (same path, signup only), both class-level `@UseGuards(CsrfGuard)`, both
      registered in a new `@Global() AuthModule` (`DUCK_AUTH_TOKEN` provider, `NestExceptionFilter`
      as `APP_FILTER`). Old `session/session.controller.ts` + `session.module.ts` deleted;
      `SessionMiddleware` now injects `DUCK_AUTH_TOKEN` and calls
      `resolveIdentityId(auth, nodeHeadersToFetch(req.headers))`. Every domain controller's
      `@UseGuards(IamGuard)` became `@UseGuards(CsrfGuard, IamGuard)` — CSRF first, matching the
      other three frameworks' "first line" idiom; harmless on `GET` since the guard no-ops on safe
      methods.
- [x] **Next.js** — `src/auth.ts` (new): `buildAuth(db)` + a generic `route()` wrapper
      (`withNextCsrf` + try/catch → `errorResponse`) typed like `withNextCsrf` itself so it
      composes directly around `withIamAccess(...)`'s returned handler, ctx included. Deleted
      `api/session/route.ts`; added `api/auth/{signin,signout,session,signup}/route.ts`.
      `src/session.ts` rewritten off `resolveIdentityId(auth, req.headers)` (already a Fetch
      `Headers`, no conversion needed). Every domain route handler wrapped in `route(...)`.
- [x] **Next.js client** — no auth client library: `dashboard/api.ts` carries `session`/`signIn`/
      `signUp`/`signOut` as plain `fetch` calls to `/api/auth/*`. `dashboard/login-form.tsx` is
      plain-markup sign-in/sign-up forms plus the seeded-user quick-fill buttons, and reports back
      through `onSignedIn`. `dashboard/page.tsx` holds the session status itself; `subject`/`scope` (→
      `userId`/`companyId`) are read off the same `/api/me/permissions` call `usePermissions`
      already makes, rather than a second fetch. `dashboard/api.ts`'s `request()` dropped the
      `token` param, added `credentials: 'include'`, and reads the `duck-csrf` cookie itself to
      set `x-csrf-token` on mutating calls (the transport runs `secure: false` for local dev, so
      the cookie is never `__Host-` prefixed — hardcoded to match).
- [x] Signup creates its own company: DuckMarket is multi-tenant, so a brand-new identity has
      nowhere to belong yet. `POST .../auth/signup` takes `{ email, password, name, companyName }`,
      creates a `companies` row, the identity, the `users` row, and calls
      `engine.admin.assignRole(identity.id, 'admin', companyId)`.
- [x] verify: `bunx tsc --noEmit` clean in all five packages; `bunx biome check --write` (17 files
      needed only import-order/formatting fixes, re-verified clean and re-typechecked after).
- [x] Fresh migrate + seed against a dropped/recreated `duckiam_examples`, all four servers booted,
      and exercised for real per framework: password signin → session cookie → tenant-scoped
      `GET` → mutation refused without `x-csrf-token` (`AUTH_CSRF`, 403) → same mutation accepted
      with it → signout → session back to `{session: null, identity: null}`. Also: a fresh signup
      (`newco@example.test`) refused cross-site (`Sec-Fetch-Site: cross-site` → `AUTH_CSRF`, 403,
      duck-auth's layer-1 same-origin gate — the CSRF token itself is intentionally skipped
      pre-session, per `csrf.ts`'s own comment), accepted same-origin, and its new company is
      correctly isolated (`GET /users` shows only its own founder row). NestJS's IAM guard
      confirmed still enforcing role grants under the new CSRF guard (`staff` role refused
      `update:orders`, `manager` allowed) — CSRF wiring didn't paper over authorization. Next.js's
      `/dashboard` confirmed rendering (200, no compile errors) with the new client tree.

## Hardening pass (shared business logic, transaction safety, UX)

Two chunks of business logic — signup and role reassignment — were identical copy-paste across
all four frameworks (not framework glue: no `req`/`res` types, just `auth`/`engine`/`db` calls).
Pulled both into `shared/`, alongside a real correctness fix each copy was missing.

- [x] `shared/src/signup.ts` (new) — `signUp(auth, db, assignAdmin, body)`. The old per-framework
      signup ran identity creation, password-set, two domain inserts, and role assignment as five
      unguarded awaits: any failure after the identity existed (a transient db error, a company
      name collision) left an unusable orphaned identity nothing could clean up, blocking that
      email from ever signing up again. Now: `companies`/`users` are written in one
      `db.transaction()` so neither can exist without the other, and a failure before that
      transaction commits calls `auth.identities.erase(...)` to free the email for retry. A
      failure in the final `assignAdmin` step (after the account is durable) is left alone —
      erasing there would violate `users.id`'s foreign key into the identity. All four
      `POST /auth/signup` handlers (express/hono/nest/next) now just call `signUp(...)`.
- [x] `shared/src/iam.ts` gained `isAppRole` (was a copy-pasted type guard in all four
      `users/:id/role` handlers) and `setRole(engine, db, targetId, roleId, scope)` (was the
      copy-pasted "revoke every other role in scope, then assign" loop the additive-RBAC bug fix
      from the previous round added to all four). `setRole` takes `engine` structurally
      (`{ admin: { assignRole, revokeRole } }`) rather than the shared package's own `AppEngine`
      type, because NestJS's DI-injected engine type widens the role generic to `string`; TS's
      bivariant method-parameter checking makes both instantiations satisfy the same structural
      type without a cast.
- [x] `next/src/app/dashboard/login-form.tsx` — `errorText()` now maps the handful of error codes
      a reader will actually hit (`AUTH_EMAIL_TAKEN`, `AUTH_INVALID_CREDENTIALS`,
      `AUTH_INVALID_PARAMETERS`, `AUTH_CSRF`) to plain-English copy, falling back to the raw code
      for anything else. Inputs got `<label>`s, `autoComplete` hints (`email`/`new-password` vs
      `current-password`/`name`/`organization`), a `minLength={8}` hint on signup matching
      duck-auth's default `passwords().minLength`, and a pending-state submit label.
- [x] verify: `bunx tsc --noEmit` and `bunx biome check` clean in all five packages. Dropped and
      recreated `duckiam_examples`, migrated + reseeded, booted all four servers. Regression-tested
      the extracted `setRole` against the exact bug the revoke-loop was written for: promoted
      `viewer@acme.test` to `staff` (`@company-acme:create:products` flips `true`), reverted to
      `viewer` (`create:products` flips back to `false` — the historical bug was it staying
      `true`). Confirmed signup's rollback path end-to-end via a real duplicate-email attempt on
      all four frameworks (`AUTH_EMAIL_TAKEN`, 409) and a real weak-password attempt on Next
      (`AUTH_INVALID_CREDENTIALS`, 401, matching `passwords.assertStrength`'s intentionally
      generic error — it never names which rule broke). Test signups made during verification were
      removed by dropping and reseeding the database, so the shared demo data is back to exactly
      the five seeded accounts documented above.

## Hardening pass 2 (numeric input validation)

Investigated whether NestJS's global `NestExceptionFilter` (`@Catch(AuthError)`) mishandles the
`BadRequestException`/`NotFoundException` the example app's own controllers throw directly — it
doesn't: the decorator scopes it away from them entirely, and Nest's own default filter formats
them correctly on its own. Also traced the IAM guards' generic-500 `onError` default (Express/Hono)
and confirmed it's a deliberate, documented choice (avoids leaking `err.stack` through the
framework's own default handler), not an oversight. Both were false alarms — no code changed for
either.

- [x] `shared/src/body.ts` — `readNumber` only checked `typeof value === 'number'`, so `NaN`,
      `Infinity`, negative numbers and fractions all passed. It backed exactly two fields —
      `priceCents` and `quantity` — each duplicated across all four frameworks (8 call sites), so a
      negative-quantity order or a fractional/negative price sailed through every backend
      identically: either silently written to the `integer` column or crashing the insert as an
      unhandled Postgres `invalid input syntax` 500 instead of a clean 400. Replaced with
      `readInt(body, key, min)` (`Number.isInteger` + a floor), and pinned each field's own
      business floor at the call site: `priceCents` at 0 (a free product is legitimate), `quantity`
      at 1. All 8 call sites (products create/update × 4 frameworks, orders create × 4 frameworks)
      updated; error messages now say what's actually required
      (`priceCents (non-negative integer)`, `quantity (positive integer)`).
- [x] verify: `bunx tsc --noEmit` and `bunx biome check` clean in all five packages. Live-tested
      against Express: a negative `quantity` order and a fractional `priceCents` product both now
      return 400 with the new message instead of either succeeding or crashing; a valid product
      still returns 201. The one test row created during verification was deleted directly rather
      than dropping the database, since nothing else was written.

## Hardening pass 3 (delete guards: FK violations were crashing two endpoints)

None of `users.companyId`/`products.ownerId`/`products.companyId`/`orders.ownerId`/
`orders.companyId` in `shared/src/schema.ts` declare `onDelete`, so Postgres defaults to
`NO ACTION`. `DELETE /companies/:id` and `DELETE /users/:id` are both IAM-permitted, advertised
operations in all four frameworks, but neither checked for dependents first — so calling either
against a company/user that still has rows referencing it (which, in practice, is almost every
real case: a company always has its own admin, plenty of seeded users own a product or order)
threw an unhandled foreign-key-violation error, masked by the app's own generic error handler
into an unhelpful `AUTH_MISCONFIGURED` 500. Live-confirmed both crashes before fixing: deleting
`staff@acme.test` (owns 1 product + 1 order) and deleting `company-acme` (has 4 users) each 500'd.

Considered cascading the FKs instead (`onDelete: 'cascade'`) — rejected: cascading a company
delete would silently delete every member's `users` row while their duck-auth identity and
password credential stay live, the mirror image of the orphaned-identity bug `signUp` already
guards against (this time a *deletable* domain row disappearing out from under a still-signed-in
identity, rather than an identity outliving its domain row). A proactive check with a clean 409
is the correct fix, not a bigger blast radius.

- [x] `shared/src/deletion-guards.ts` (new) — `companyHasUsers(db, companyId)` and
      `userOwnsRows(db, userId)`, two `SELECT ... LIMIT 1` checks, pure db logic with no
      framework-specific types (same shape as `signup.ts`/`setRole`). Wired into all four
      frameworks' `DELETE /companies/:id` and `DELETE /users/:id` handlers, right after the
      existing tenant-ownership check and before the delete statement: a positive check now
      returns `409 Conflict` (`ConflictException` in Nest) with a message naming what's blocking
      it, instead of letting the database throw.
- [x] verify: `bunx tsc --noEmit` and `bunx biome check` clean in all five packages. Live-tested
      against Express: `DELETE /users/:id` for `staff@acme.test` and `DELETE /companies/:id` for
      `company-acme` both now return a clean 409 instead of a 500, and neither touched a row
      (confirmed `staff@acme.test` still exists afterward). Round-tripped the guard's negative case
      too: signed up a disposable account, confirmed its brand-new company correctly 409s while it
      still has its one user. Test rows were removed directly (one throwaway user + company);
      final counts confirmed back at the pristine baseline (2 companies, 5 users, 5 identities, 2
      products, 1 order).

## Hardening pass 4 (two more unvalidated write paths)

Found while re-checking the other write endpoints for the same class of gap `readInt` closed in
pass 2: two more PATCH handlers accepted input the database or downstream code couldn't actually
handle.

`PATCH /products/:id` with an empty body, or a body with no recognized fields, built an empty
`patch` object and passed it straight to `db.update(products).set(patch)`. Drizzle's `.set({})`
throws `"No values to set"` synchronously (`mapUpdateSet` in `drizzle-orm/utils.js`) — a crash
before any query even runs, surfacing as the same generic 500 the delete-guard pass found.
Live-confirmed: `PATCH /products/product-widget-acme` with `{}` 500'd.

`PATCH /orders/:id` accepted `status` as any non-empty string, writing it straight into the
`status` text column with zero validation — there's no Postgres CHECK/enum backing it.
Live-confirmed by sending `{"status":"totally-not-a-real-status!!"}`: it returned `200 {"ok":true}`
and the garbage string landed in the live `orders` row, silently corrupting a real record with no
error at all (worse than the 500s above — this one succeeds).

- [x] `products` PATCH (all four frameworks) — guard added right before the update: an empty
      `patch` object now returns a clean 400 (`name (string) or priceCents (non-negative integer)
      required`) instead of reaching drizzle's throw.
- [x] `shared/src/schema.ts` — added `ORDER_STATUSES` (`pending`/`shipped`/`delivered`/`cancelled`,
      matching the column's own seeded default and the only values any handler ever writes) and
      `isOrderStatus`, a type guard, next to the `orders` table definition — same pattern as
      `isAppRole` already used for `roleId` in the users role-assignment routes.
- [x] `orders` PATCH (all four frameworks) — `status` now checked against `isOrderStatus` before
      writing; an invalid or missing value returns 400 with `status must be one of pending,
      shipped, delivered, cancelled` instead of writing anything.
- [x] verify: `bunx tsc --noEmit` clean in all four frameworks; `bunx biome check --write` clean
      (auto-fixed import ordering in 5 files, no logic changes). Live-tested against Express: `PATCH
      /products/:id` with `{}` now returns 400 instead of 500, a valid `{"priceCents":...}` body
      still returns 200; `PATCH /orders/:id` with an invalid status now returns 400 with the new
      message, a valid `"pending"` still returns 200. The order row polluted with
      `"totally-not-a-real-status!!"` during discovery was reset back to `pending` (its original
      seeded value) via the same verified PATCH path, not a raw SQL write — confirming the fix
      end-to-end rather than just papering over the test data.

## Hardening pass 5 (signup accepted any string as an email)

Re-checked every remaining write path for the same class of gap the last two passes closed, and
found one more: `signUp` (`shared/src/signup.ts`, the one implementation all four frameworks'
`POST /auth/signup` call) read `email` with plain `readString` — any non-empty string. Neither
duck-auth's `identities.create` nor the `users.email` column (`text().notNull().unique()`, no
Postgres CHECK) checks that it looks like an email. Live-confirmed: `POST /auth/signup` with
`"email":"not-an-email"` returned `201` and created a real identity, a real company, and a real
`users` row — durable garbage, not a crash, which is arguably worse than the earlier 500s since
nothing about the response hints anything is wrong.

- [x] `shared/src/body.ts` — added `readEmail(body, key)`, same shape as `readInt`: reads the
      field and returns it only if it passes a light format check (`/^[^\s@]+@[^\s@]+\.[^\s@]+$/`
      — one `@`, a label on each side, no whitespace). Not RFC 5322; just enough to reject garbage
      before it becomes a durable row across three tables.
- [x] `shared/src/signup.ts` — swapped `readString(body, 'email')` for `readEmail(body, 'email')`.
      Falls through the existing `if (!email || ...) throw new AuthError('AUTH_INVALID_PARAMETERS')`
      check unchanged, so no new error code or response shape was needed — same 400 all four
      frameworks already return for any other missing/invalid signup field. `readString` for
      `email` had exactly one call site, so no other write path needed the same swap.
- [x] verify: `bunx tsc --noEmit` clean in all four frameworks; `bunx biome check` clean, no fixes
      needed. Live-tested against Express: `POST /auth/signup` with `"not-an-email"` now returns
      400 `AUTH_INVALID_PARAMETERS` and creates nothing; a valid email still returns 201 and
      creates identity + company + user as before. Both test artifacts (the pre-fix garbage row
      and the post-fix valid-signup row) were deleted directly across `users`/`companies`/
      `auth_identities`; final counts confirmed back at the pristine baseline (2 companies, 5
      users, 5 identities, 2 products, 1 order).

Also checked the more likely real-world case next to it — signing up with an email that's
already taken. That's handled correctly: duck-auth's own `identities.create` rejects it with a
clean `409 AUTH_EMAIL_TAKEN` before any transaction starts, confirmed live, and confirmed it
leaves no dangling company/user row. No code changed for that case.

## Hardening pass 6 (whitespace-only names)

Kept auditing the same free-text fields pass 5 fixed `email` for, for the same gap: `readString`
treats `"   "` as present, since it's non-empty by `typeof`/length even though it's meaningless as
a display name. Every place a caller names something — `signUp`'s `name`/`companyName`, a
company's `PATCH` name, a product's `name` on create and update — read the field this way. Every
one of them is a completely free-text `text` column with no Postgres CHECK. Live-confirmed:
`POST /auth/signup` with `"name":"   ","companyName":"   "` returned 201 and created a company and
a user whose only visible identifier was three spaces.

- [x] `shared/src/body.ts` — added `readTrimmedString(body, key)`: reads the field, trims it,
      returns `undefined` if nothing's left. Deliberately not applied to `password` (trimming a
      credential silently would be its own bug, not a fix) or `email` (already shape-checked by
      `readEmail`, and email addresses can legitimately have meaningful non-space characters
      `readTrimmedString` shouldn't touch) — only free-text labels.
- [x] Swapped `readString(..., 'name')` → `readTrimmedString(...)` at all 14 call sites: `signUp`'s
      `name` and `companyName` (1 file), products create + update `name` (4 frameworks × 2), and
      companies update `name` (4 frameworks). Storage now holds the trimmed value, not whatever
      leading/trailing whitespace the request arrived with.
- [x] verify: `bunx tsc --noEmit` clean in all four frameworks; `bunx biome check` clean, no fixes
      needed. Live-tested against Express: a whitespace-only `PATCH /companies/:id` name and a
      whitespace-only `POST /products` name both now return 400 instead of succeeding; `PATCH
      /companies/:id` with `"  Acme Co  "` returned 200 and stored `"Acme Co"` (confirmed via
      direct query, and it happened to restore the row to its exact original seeded value, so no
      further cleanup was needed); `POST /auth/signup` with whitespace-only `name`/`companyName`
      now returns 400 and creates nothing (row counts confirmed unchanged, no cleanup needed).

## Hardening pass 7 (malformed JSON body → 500, on Express and Hono)

Checked every framework against a genuinely likely real-world mistake — a client sending a
truncated or malformed JSON body — rather than another unvalidated-field sweep. duck-auth's shared
`errorToHttp` (used by every framework's own top-level error handler) treats anything that isn't
an `AuthError` as a 500 `AUTH_MISCONFIGURED`, and a JSON parse failure isn't one. Checked all four:

- **Next**: already safe everywhere — `/auth/signup` uses duck-auth's own `readBodyJson`, which
  already swallows a `JSON.parse` failure to `null`; every other route reads its body with
  `req.json().catch(() => undefined)`. No fix needed.
- **Nest**: already safe — Nest's own default exception filter duck-types on `err.statusCode`, and
  its underlying body-parser's `SyntaxError` already carries `statusCode: 400`, so Nest formats it
  correctly before ever reaching this app's own code. Live-confirmed on both `/auth/signup` and
  `POST /products`: a malformed body returns Nest's own clean `400 Bad Request`. No fix needed.
- **Express**: real bug. `express.json()` (global middleware, ahead of every route) throws
  synchronously on a malformed body; Express 5 forwards the rejection to this app's own `onError`,
  which had no special case and fell through to `errorToHttp`'s generic 500. Live-confirmed:
  `POST /auth/signup` with `{not valid json` returned `500 AUTH_MISCONFIGURED` instead of a 400 —
  and since `express.json()` runs ahead of every router, this hit every POST/PATCH endpoint in the
  app, not just signup.
- **Hono**: real bug, but narrower. `/auth/signup` already uses `readBodyJson` (same as Next/Nest,
  safe), but every other route (`products`, `orders`, `companies`, `users`) reads its body with
  `c.req.json()` directly, which throws a bare `SyntaxError` straight into `app.onError` — which
  had the same gap as Express's. Live-confirmed: `POST /auth/signup` was already safe (400), but
  `POST /products` with a malformed body returned `500 AUTH_MISCONFIGURED`.

- [x] `express/src/server.ts` — the app's own `onError` now recognizes
      `err instanceof SyntaxError && err.type === 'entity.parse.failed'` (body-parser's own,
      documented discriminator for exactly this failure) before falling through to `errorToHttp`,
      answering `400 { error: 'invalid JSON body' }` instead.
- [x] `hono/src/server.ts` — `app.onError` now recognizes `err instanceof SyntaxError` (Hono/Bun's
      JSON parse failure carries no extra discriminator, but nothing else in this app throws a raw
      `SyntaxError`) before falling through to `errorResponse`, same 400 body.
- [x] verify: `bunx tsc --noEmit` clean in both frameworks; `bunx biome check` clean, no fixes
      needed. Live-tested against both (dev servers on 3100/3200, plus Nest on 3300 to confirm its
      already-correct behavior): malformed JSON on `/auth/signup` and on `POST /products` now
      returns 400 on both Express and Hono; re-tested a genuine `AuthError` case (duplicate-email
      signup) on both afterward to confirm no regression — still returns the correct
      `409 AUTH_EMAIL_TAKEN` envelope, not the new 400. No test data was created by any of the
      malformed-body requests (all rejected before reaching the database), so no cleanup was
      needed; row counts confirmed unchanged (2 companies, 5 users, 5 identities) after stopping
      all three dev servers.

## From-scratch setup verification

Everything above was found by testing against a database that had accumulated a whole session's
worth of manual pokes. To check the README's own setup instructions actually work for someone
starting cold, dropped and recreated `duckiam_examples`, then followed the README exactly:

- `bun run db:setup` from `express/` only — confirmed all 12 tables created and seed row counts
  correct (2 companies, 5 users, 5 identities, 2 products, 1 order).
- Ran the README's documented curl walkthrough verbatim against the freshly-seeded Express server:
  sign in, read session, `PATCH /companies/:id` without a CSRF header (403), same request with the
  header (200) — every step matched exactly. Reverted the walkthrough's own company-rename
  mutation afterward.
- Booted Hono and Nest against the *same* already-seeded database, without running their own
  `db:setup`, and confirmed all three frameworks read an identical `createdAt` timestamp on
  `company-acme` — proving the README's "all four frameworks point at the same shared Postgres
  database" claim is actually true, not just documented.

No new bugs found in this pass; it verified existing correctness rather than fixing anything.

## Hardening pass 8 (`next build` — and the repo-root `bun run build` — crashed on this example)

Reviewed the Next.js dashboard (`src/app/dashboard/{page,login-form,api,duck-market}.tsx`) — the
one genuinely new surface this session, a real client using `useSignIn`/`useAuthClient().signUp`
and a real `<AccessProvider>` tree, not just another API-only backend. No logic bugs found: body
reads, tenant filters, and CSRF header plumbing all matched the already-hardened pattern from the
other three frameworks. Also traced the `sessionOfSync` comment's claimed invariant ("safe because
`withIamAccess` always awaits `getUserId` before evaluating `getScope`") against
`packages/duck-iam/src/server/next/index.ts` and `iamRunAccessCheck` in
`packages/duck-iam/src/server/generic/index.ts` — confirmed true, not just asserted.

Ran Next's own `tsx`-based `db:setup` (a code path distinct from the other three frameworks'
`bun run src/db/migrate.ts`) against the already-seeded shared database — confirmed idempotent, row
counts unchanged.

Then ran `bun run build` (the standard Next.js command, and — since `examples/duck-iam/*` is a
real workspace member — also what the **repo root's own `bun run build`** invokes via turbo) and it
crashed:

```
Error [AuthError]: AUTH_MISCONFIGURED
  production strict() checks failed:
  - AuthMemoryLimiter rejected in production
  - Event bus required
  - AuthCookieTransport secure=false rejected in production
  - baseUrl 'http://localhost:3400' must use https:// in production
  - no `lockout` event handler subscribed
```

Root cause: `next build`/`next start` unconditionally force `NODE_ENV=production`, and Next's build
step imports every route module — including its top-level `export const auth = buildAuth(db)` —
to statically collect its configuration. `buildAuth` (`shared/src/auth.ts`) intentionally uses a
dev-only config (in-memory limiter, insecure cookie, no event bus) because these examples
demonstrate the authorization engine, not duck-auth's production hardening surface — so
duck-auth's `strict()` gate correctly refuses it the moment `NODE_ENV` says production. That gate
is doing its job; the bug is that this example ever exercised it. None of the other three
frameworks hits this: none of them has a `build` script, and their `start` scripts (`bun
src/server.ts`) never set `NODE_ENV=production` either — by design, all four frameworks in this
suite are dev-only, and only Next's tooling has a command that silently forces otherwise.

- [x] `next/package.json` — removed the `build` and `start` scripts. Matches the other three
      frameworks' shape exactly (`dev`, `db:migrate`, `db:seed`, `db:setup` only); `next start`
      needs a `next build` output anyway, so it goes too.
- [x] verify: `bunx turbo run build --filter=@examples/duck-iam-next` now skips the package
      entirely (no `build` script to run) and the filtered task graph completes green — confirming
      the repo-root `bun run build` is no longer broken by this example.
- [x] verify: `bun run db:setup` (Next's own `tsx` path) then `bun run dev`, live-tested the full
      flow end-to-end on port 3400 — guest session (`{"session":null}`), sign in as
      `admin@acme.test`, authed session, `GET /api/me/permissions` (correct per-action map for the
      `admin` role), `PATCH /companies/:id` without CSRF (403 `AUTH_CSRF`) then with it (200,
      reverted after), `DELETE` on the caller's own user row (403, confirming the dashboard's own
      documented `deny-self-account-delete` claim is real and not just UI copy), malformed JSON on
      `POST /products` (clean 400, not 500), sign out, session back to guest. `bunx tsc --noEmit`
      and `bunx biome check` clean across the whole `examples/duck-iam` tree (99 files). Row counts
      confirmed unchanged throughout (2 companies, 5 users, 5 identities, 2 products, 1 order); dev
      server stopped, port 3400 confirmed free afterward.

## Hardening pass 9 (three smaller findings from a full read of the last unaudited files)

Read every remaining file that hadn't been read this session: all of NestJS (`main.ts`,
`app.module.ts`, every controller/module, `csrf.guard.ts`, `session.ts`) to check it for the same
class of bugs already fixed in the other three frameworks, plus `shared/src/{iam,schema,
deletion-guards,db,seed}.ts`. Nest matched the already-hardened pattern everywhere (all routes use
`readTrimmedString`/`readInt`/deletion guards correctly) — no new bugs there. Three smaller,
real findings elsewhere:

- **`shared/src/auth.ts`'s `APP_URL` fallback was hardcoded to Next's port.** `const APP_URL =
  process.env.APP_URL ?? 'http://localhost:3400'` is shared by all four frameworks, and only
  Next's `.env.example` has any reason to imply 3400 — Express/Hono/Nest's `.env.example` never
  set `APP_URL`, so all three silently got `baseUrl: 'http://localhost:3400'` regardless of which
  port they actually run on. Currently harmless (verified by grepping duck-auth core: `baseUrl` is
  only read by the email-verification/password-reset/account-deletion flows, none of which this
  example wires up), but wrong and confusing on its face, and would silently produce broken links
  in any callback URL the moment one of those flows got added later. Fixed by deriving the fallback
  from `PORT` instead: `` `http://localhost:${process.env.PORT ?? 3400}` `` — every framework
  already sets/reads `PORT` for its own server, so this now naturally resolves to the actual
  running port with no framework-specific code. Verified live for all four ports by forcing
  `NODE_ENV=production` (the only thing that reads `baseUrl` at runtime path is the `strict()`
  gate — see pass 8) and reading the computed value out of the thrown error's `meta.detail`:
  3100/3200/3300/3400 all correct, including the no-`PORT`-set case (Next), which still correctly
  falls back to 3400.
- **The Next dashboard's order-status dropdown was missing one of the four valid statuses.**
  `shared/src/schema.ts`'s `ORDER_STATUSES` is `['pending', 'shipped', 'delivered', 'cancelled']`,
  but `duck-market.tsx`'s `<select>` for changing an order's status only offered `['pending',
  'shipped', 'cancelled']` — a user could never mark an order "delivered" through the one real UI
  in this suite, even though the backend fully accepts it. Not importable from the shared schema
  module directly (that pulls in `drizzle-orm/pg-core`, which must never reach a client bundle —
  same reasoning already documented on `@/access`'s `import type` boundary and on the existing
  `ROLE_OPTIONS` hand-duplicate a few lines above it in the same file). Fixed by adding a matching
  `ORDER_STATUS_OPTIONS` hand-duplicate, following that exact existing pattern.
- **Stale dev-database state left over from an earlier session's imperfect cleanup.** The
  from-scratch verification round (previous section) ran the README's own curl walkthrough, which
  renames `company-acme` to `"Acme Renamed"` — the README documents this as a one-shot demo with no
  revert step. An earlier pass in this session added its own revert step, but reverted to `"Acme"`
  rather than `seed.ts`'s actual seeded value `"Acme Co"` (`upsertCompany('company-acme', 'Acme
  Co')`), and since seeding uses `onConflictDoNothing()`, re-running `db:setup` against the
  existing row would never have self-corrected this — the shared dev database would have stayed
  permanently one word short of what a genuine fresh clone produces. Caught by comparing the live
  `select name from companies` output against `seed.ts` directly. Fixed with a direct `UPDATE`
  (data correction, not a code change) restoring `"Acme Co"`.

- [x] verify: `bunx tsc --noEmit` clean in all five packages (`shared`, `express`, `hono`, `nest`,
      `next`); `bunx biome check` clean across all 99 files (31 in `next` alone after the
      dashboard edit) — no fixes needed. Row counts confirmed unchanged (2 companies, 5 users, 5
      identities, 2 products, 1 order) and `company-acme`'s name confirmed corrected to `"Acme Co"`
      after the fix. No dev servers were left running (ports 3100-3400 all confirmed free).

## Verification round: concurrency, password policy, cross-framework liveness

No new code bugs; three more angles this session hadn't tried yet, each confirmed already correct
rather than fixed:

- **All four frameworks boot concurrently against the shared database with no conflicts.** Ran all
  four `bun run dev` at once (3100/3200/3300/3400), hit each one's session endpoint, got the
  identical `{"session":null,"identity":null}` guest response from all four, and confirmed clean
  startup logs (Nest's full route table, Next's Turbopack ready line) with nothing unusual. Also
  confirmed the root `check`/`lint`/`format`/`fix` scripts (`biome check|lint|format --write
  packages/ tooling/`) never touch `examples/` at all — a pre-existing, deliberate scoping choice,
  not a gap introduced this session — so `bunx biome check examples/duck-iam` (what every pass this
  session has actually run) is the correct manual substitute, and the root `ci` script's `turbo run
  build` is exactly what pass 8 fixed.
- **Password policy (`assertStrength`, `rejectCommon`) is genuinely active, not just documented.**
  `LoginForm`'s copy claims a signup password can fail for being "too short or too common"; verified
  live against Express: an 8-char floor is enforced (a 3-char password → `401
  AUTH_INVALID_CREDENTIALS`, correctly rolled back with no identity ever created, since
  `assertStrength` runs before `identities.create()`), and `rejectCommon`'s small exact-match list
  (`password`, `password1`, `12345678`, etc. — 9 entries, checked in `passwords.constants.ts`) does
  fire for a password literally on that list. A password merely *common-sounding* but not literally
  on the list (tried `"password123"`) is accepted — that's a real limitation, but it's duck-auth
  core's own narrow list, not anything wrong in this example's wiring. Cleaned up the one row this
  accepted test created (identity + company + user + assignment, via direct SQL matching the actual
  FK deletion order) and confirmed row counts back to baseline afterward.
- **Concurrent signup with an identical email has no TOCTOU race.** Fired 5 truly concurrent (not
  sequential) `POST /auth/signup` requests with the same email at Express — exactly one returned
  `201`, the other four `409 AUTH_EMAIL_TAKEN`, no duplicate identities and no partially-created
  rows from the losers. Cleaned up the one successful signup's rows afterward and confirmed row
  counts back to baseline.

- [x] verify: row counts and `company-acme`'s name confirmed at true baseline after every test in
      this round (2 companies, 5 users, 5 identities, 2 products, 1 order, `"Acme Co"`); all four
      dev servers stopped, ports 3100-3400 confirmed free.

## Known, deliberately-deferred limitation

`setRole` (`shared/src/iam.ts`) revokes the target's other roles in a company, then assigns the new
one, as two-plus sequential `engine.admin` calls — not one transaction. A crash between the revoke
and the assign leaves the user with no role in that company until retried. Investigated wrapping it
in `db.transaction()` (the same pattern `signUp` already uses for its `companies`/`users` insert):
doesn't work here, because `engine.admin.revokeRole`/`assignRole` write through whichever
`IamDrizzleAdapter` instance backs the long-lived, cached `engine` singleton every framework already
uses for its request-time permission checks. Building a second, transaction-scoped engine just for
this call would mutate through a *different* adapter instance than the one serving live
authorization checks — trading a rare mid-crash inconsistency for a guaranteed staleness window
(the singleton's own cache wouldn't see the change) on every single role assignment. Fixing this
properly needs `@gentleduck/iam`'s admin API to accept an externally-supplied transaction handle,
which is package-level work, not something to hack around in an example. Left as-is; noted here so
it isn't rediscovered as a surprise.

## Hardening pass 10 (Next dashboard: loading/error/empty states, accessibility, responsive layout)

No visual/browser testing was available this session (no Playwright installed anywhere in the
monorepo, no browser automation tool registered) — this pass is a deliberately deeper code-only
substitute: re-read `page.tsx`, `duck-market.tsx`, `login-form.tsx`, and `globals.css` specifically
hunting for UI-quality issues rather than logic/security bugs. One genuine bug found and fixed, plus
four smaller UI-honesty/accessibility gaps:

- **Bug: a permissions-fetch failure hung the dashboard on "Loading permissions..." forever.**
  `usePermissions` (`packages/duck-iam/src/client/react/index.ts`) exposes `error`, and on a
  rejected fetch it sets `loading` back to `false` — but `page.tsx` destructured only `{ permissions,
  loading }`, never `error`. Since `me` is only set inside the success path of `fetchPermissions`, a
  rejected fetch left `me` at its initial `null` forever, so `!me?.scope` stayed `true` and the
  `loading || !me?.scope` guard kept showing the loading message indefinitely — indistinguishable
  from a slow network, with no error and no way to recover short of a full page reload. Fixed by
  destructuring `error`/`refetch` and adding a real error branch (message + Retry button calling
  `refetch()`) ahead of the loading check.
- **`duck-market.tsx`'s `reload()` silently swallowed every fetch failure into an empty/null
  state** (`api.company(...).then(setCompany, () => setCompany(null))` and similarly for
  users/products/orders) — a backend 500 or network blip rendered identically to "no permission to
  see this company" or "no orders yet", with nothing telling the user a fetch actually failed. Fixed
  by routing each rejection through the existing `notice` state with a `Couldn't load <resource>:
  <message>` string, so a real failure is now visible instead of silently mimicking an empty state.
- **Error/status text had no ARIA live region.** `login-form.tsx`'s error paragraph and
  `duck-market.tsx`'s `notice` paragraph were plain `<p>`s — a screen-reader user submitting a form
  or triggering an action (delete/rename/assign role) got no automatic announcement of success or
  failure unless they happened to navigate to that exact spot afterward. Fixed with `role="alert"`
  on the login form's error and `role="status"` on the dashboard's notice (mixed success/failure
  content, so polite rather than assertive).
- **Per-row controls had no accessible name distinguishing one row from another.** Three tables
  (products, orders, users) each render one "Delete" button or one `<select>` per row with identical
  visible text/no label across rows — a screen reader user navigating by control (not by reading the
  whole row) hears "Delete, Delete, Delete..." or "Combo box, Combo box..." with no way to tell which
  row it belongs to. Added `aria-label`s naming the row's subject (product name, order's product
  name, or user email) to every per-row button/select.
- **Tables had no overflow handling for narrow viewports.** `globals.css` never defined anything to
  contain a wide table (5-column orders table with a status `<select>`, or the users table) at phone
  width — `main`'s own 16px side gutter doesn't help once a row's content is wider than the
  viewport. Added a `.table-wrap { overflow-x: auto }` class and wrapped all three data tables
  (products/orders/users) in it, so a too-wide table scrolls horizontally inside its own box instead
  of blowing out the page.

Not fixed, judged acceptable as-is: no loading spinner/skeleton (plain "Loading..." text is honest
and sufficient for a demo); empty tables render with headers and no rows rather than an explicit
"no products yet" message (low-value polish, not a correctness or accessibility issue); the
company-rename `prompt()` dialog (native browser UI, already accessible, just minimal); mode-switch
buttons in `LoginForm` stay enabled while a submit is `pending` (a user could switch sign-in/sign-up
mode mid-request — cosmetically odd but not exploitable, since `submit` still reads current state at
call time and the in-flight request's own result is what actually lands).

- [x] verify: `bunx tsc -p tsconfig.json --noEmit --pretty false --skipLibCheck` clean in `next`;
      `bunx biome check` clean on all four touched files (`page.tsx`, `duck-market.tsx`,
      `login-form.tsx`, `globals.css`).

## Hardening pass 11 (`engine.healthCheck()` was wired into none of the four frameworks)

Audited `@gentleduck/iam`'s full feature surface against what the four examples actually exercise
(RBAC grants, inheritance, scoped roles, deny-overrides + cross-policy combine, ownership
conditions, admin role management, batch `permissions()`, caching — all genuinely covered). The one
real gap: `engine.healthCheck()` (adapter liveness probe + cache hit rate, `IamEngineTypes.IHealth`)
existed on every engine instance already built but was called nowhere — no framework exposed a
liveness endpoint, which any real deployment needs. Added `GET /health` (`GET /api/health` in Next)
to all four, unauthenticated (a load balancer has no session), one route file each matching each
framework's existing per-domain router/controller pattern, returning the health object with `200`
when `ok`, `503` otherwise.

Deliberately not added: `explain()` (needs a `development`-mode engine — the shared engine is
`production` by default and flipping that changes `permissions()`'s return shape for every route;
a second parallel engine just for tracing was judged not worth the drift risk for a demo), the
devtools panel (`@gentleduck/iam/dt` expects a live engine object in the same process as the
component — this app's engine is Postgres-backed and lives server-side only, so it cannot cross
into the Next dashboard's client bundle without a different architecture), and hooks / nested
and/or/not conditions / non-default combining algorithms (none of these are missing capability —
they're optional diagnostics or alternate patterns a shopping-cart demo has no natural need for,
and forcing them in would be exactly the kind of feature-checkbox bloat this pass was told to avoid).

- [x] verify: `bunx tsc --noEmit` clean in all four frameworks; `bunx biome check` clean on all 8
      touched/created files. Live-curled `/health` (`/api/health` for Next) against all four running
      dev servers — every one returned `200 {"ok":true,"adapter":"ok","cacheHitRate":0,...}`. All
      four dev servers stopped afterward, ports 3100-3400 confirmed free.
