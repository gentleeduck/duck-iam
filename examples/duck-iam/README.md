# duck-iam real-world examples

Four standalone backends — one per framework — each demonstrating a different
`@gentleduck/iam` server adapter (`server/express`, `server/hono`, `server/nest`,
`server/next`), authenticated for real by `@gentleduck/auth` (`passwords()` + cookie sessions,
the same shape as `examples/duck-auth`). Next.js additionally carries a real React client
(`@gentleduck/auth/client/react` + `@gentleduck/iam/client/react`) in its `src/app/dashboard`.

All four point at the **same** shared Postgres database, so the same seeded identities, the
same rows, and the same IAM decisions are visible from whichever framework you hit.

## Shared package (`examples/duck-iam/shared`)

The domain — schema, IAM config, auth config, seed data, body-parsing helpers, and the db
connection factory — is defined **once** and imported by all four frameworks, not duplicated
per backend:

- `@examples/duck-iam-shared/schema` — drizzle `pgTable`s for `companies`/`users`/`products`/
  `orders`, plus a re-export of the iam adapter's own tables from
  `@gentleduck/iam/adapters/drizzle/pg` and duck-auth's own tables from
  `@gentleduck/auth/adapters/drizzle/pg`. `users.id` is a real `uuid` foreign key into
  `authIdentities.id` — one signup creates one identity and one `users` row, never a separate
  join table. `email`/`name` stay denormalized on `users` (kept in sync at write time) so
  DuckMarket's own queries never join into `auth_identities`. Also `ORDER_STATUSES` and
  `isOrderStatus` — `orders.status` is a plain `text` column with no Postgres CHECK behind it, so
  every framework's `PATCH /orders/:id` validates against this guard before writing.
- `@examples/duck-iam-shared/iam` — the `createIam` schema, roles, the `deny-self-account-delete`
  policy, `buildEngine(db)` (wraps a caller-supplied `NodePgDatabase` in an `IamDrizzleAdapter`,
  `dialect: 'pg'` the default), and two helpers so every framework's `POST /users/:id/role`
  handler shares one implementation: `isAppRole` and `setRole(engine, db, targetId, roleId,
  scope)` (revokes every other role the target holds in that scope before assigning the new one —
  `assignRole` alone is additive RBAC, but DuckMarket's model is one role per company).
- `@examples/duck-iam-shared/auth` — `buildAuth(db)`, wiring `@gentleduck/auth`'s
  `drizzlePgAdapter`, a `passwords()` provider, and a cookie transport over the same `db`; and
  `resolveIdentityId(auth, headers)`, the one place every framework's session middleware calls
  into duck-auth.
- `@examples/duck-iam-shared/signup` — `signUp(auth, db, assignAdmin, body)`, the one
  implementation every framework's `POST /auth/signup` calls: creates the identity and password
  credential, writes the `companies`/`users` rows in a single db transaction, then assigns admin.
  A failure before that transaction commits erases the just-created identity so the email is free
  to retry, rather than leaving an orphaned account nothing can clean up.
- `@examples/duck-iam-shared/seed` — `seedDb(db)`, the same deterministic seed data for every
  framework — now real duck-auth identities with real password credentials, not placeholder rows.
- `@examples/duck-iam-shared/body` — tiny runtime-narrowing JSON body helpers: `readString`,
  `readInt(body, key, min)` for the two `integer` columns (`priceCents`, `quantity`) — rejects
  `NaN`/`Infinity`/negatives/fractions, not just non-numbers, so a bad value gets a clean 400
  instead of silently corrupting a row or crashing the insert — `readEmail(body, key)`, a light
  format check (`local@domain.tld` shape) `signUp` uses, since neither duck-auth nor the `users`
  table's plain `text` column checks that an email looks like one — and `readTrimmedString(body,
  key)`, used for every free-text name (`signUp`'s `name`/`companyName`, a company's or product's
  `name`), which trims and rejects whitespace-only input `readString` would otherwise accept.
- `@examples/duck-iam-shared/deletion-guards` — `companyHasUsers(db, companyId)` and
  `userOwnsRows(db, userId)`. None of the domain FKs cascade, so `DELETE /companies/:id` and
  `DELETE /users/:id` check first and answer `409 Conflict` when the target still has dependents,
  instead of letting Postgres refuse the statement with an unhandled constraint-violation error.
- `@examples/duck-iam-shared/db` — `createDb()`, a `pg.Pool` + `drizzle-orm/node-postgres`
  connection factory. Each framework calls this once, from its own `src/db/index.ts` — a
  separate OS process can't share a live pool object, but every process points at the same
  database.

`drizzle-kit generate` runs once, from `shared/`, against `shared/src/schema.ts`; the resulting
SQL in `shared/drizzle/` is the single migration history every framework's `db:migrate` applies.

## Database

Postgres, not SQLite: all four examples share one database, `duckiam_examples`, on the existing
iryss Postgres container (`docker ps` → `iryss-postgres`, `iryss`/`iryss`, port 5432 — the same
instance iryss's own dev stack uses, in its own database).

Each of the five packages (`shared/`, `express/`, `hono/`, `nest/`, `next/`) reads its config from
its own `.env`, gitignored, copied from the `.env.example` checked into that directory:

```sh
cp .env.example .env   # run inside each package directory you touch
```

`DATABASE_URL` is required — there is no hardcoded fallback, so a missing `.env` fails loudly
instead of silently connecting somewhere unexpected. `PORT` is optional per framework (defaults
match the table below). Bun loads `.env` automatically for `express`/`hono`/`nest`/`next dev`;
the one-off `db:migrate`/`db:seed` scripts under `next` run via `tsx --env-file=.env` since `tsx`
doesn't load it on its own.

## The domain: DuckMarket

Modeled on iryss's own marketplace-api authorization design (`.claude/skills/building-a-module/SKILL.md`,
part 4 "IAM"), scaled down to something a reader can hold in their head in one sitting:

- **Resources:** `companies`, `users`, `products`, `orders`
- **Actions:** `read`, `create`, `update`, `delete`, `manageRoles` — a fixed vocabulary, granted
  action-by-action per role (no blanket `grantCRUD`, matching iryss's own convention).
- **Scope:** `company` — every role assignment is scoped to the company it applies to, the same
  way iryss resolves scope from the actor's own grants (`@AuthorizeCompany`). iryss also resolves
  a second, independent scope from the request's host (`@AuthorizeMarketplace`); these examples
  implement only the company-scope source, to keep four framework builds in scope, and call that
  trade-off out here rather than pretend to replicate the whole thing.
- **Roles:** `viewer < staff < manager < admin`, each inheriting the last and granting more verbs.
- **Ownership condition:** a `deny-self-account-delete` policy — `deny` on `delete:users` when
  `isOwner('resource.attributes.id')` — under `algorithm('deny-overrides')`, the exact shape of
  iryss's own canonical example.
- **Anonymous subject:** an unauthenticated request resolves to subject id `anonymous`, seeded
  with zero role assignments anywhere — fail-closed, never `null`.
- **Derived permission batch:** `GET /me/permissions` calls `engine.permissions()` once per
  request and returns exactly what the guards enforce, the same shape as iryss's own
  `GET /auth/permissions`.

duck-iam itself is authorization only — it has no opinion on how a subject proves who it is.
These examples used to stub that out with a fake `POST /session { email }` bearer token. They now
run real authentication through `@gentleduck/auth`: password credentials, cookie sessions, and
CSRF-guarded mutations, wired the same way `examples/duck-auth` wires them.

- **`POST /auth/signin`, `POST /auth/signout`, `GET /auth/session`** — duck-auth's own handlers
  (`mountSignIn`/`nextSignIn`/etc per framework), mounted directly. They guard their own CSRF.
- **`POST /auth/signup`** — this app's own route, not duck-auth's: it creates the identity, sets
  the password credential, creates a brand-new `companies` row (DuckMarket is multi-tenant, so a
  fresh signup needs somewhere to belong), writes the `users` row, and assigns the new identity
  `admin` in its own company. Body: `{ email, password, name, companyName }`.
- **Every mutating domain route** (`companies` PATCH/DELETE, `users` POST role/DELETE, `products`
  POST/PATCH/DELETE, `orders` POST/PATCH/DELETE) is CSRF-guarded the same way duck-auth's own
  `accountRouter`/`mfaRouter` examples guard theirs — first line inside the router/controller/
  wrapper, before the handler runs. `GET` routes are unguarded; CSRF only applies to unsafe
  methods, so wrapping them is a no-op that keeps the pattern uniform.
- **Session resolution** — each framework's session middleware calls
  `resolveIdentityId(auth, headers)` against the request's cookie, then looks up the `users` row
  for `companyId`. No token, no header parsing; a request with no valid session cookie resolves to
  `ANONYMOUS_SUBJECT_ID`, same fail-closed default as before.
- **Scope** — password + sessions only, matching duck-auth's `passwords()` provider. No MFA,
  magic-link, OAuth, email verification, or password reset in these examples; that's duck-auth's
  own `examples/duck-auth` to show, not duck-iam's.
- **Seed data is now real accounts.** `seedDb` creates (or reuses, by email) a real duck-auth
  identity per seeded user and sets a real password credential. All five demo accounts share one
  password: `duckiam-examples`.

Curl walkthrough (any framework — this uses Express on 3100):

```sh
# Sign in, keep the cookie jar.
curl -c cookies.txt -X POST http://localhost:3100/auth/signin \
  -H 'content-type: application/json' \
  -d '{"providerId":"password","input":{"email":"admin@acme.test","password":"duckiam-examples"}}'

# Read your own session.
curl -b cookies.txt http://localhost:3100/auth/session

# A mutation without the CSRF header is refused (AUTH_CSRF, 403).
curl -b cookies.txt -X PATCH http://localhost:3100/companies/company-acme \
  -H 'content-type: application/json' -d '{"name":"Acme Renamed"}'

# Read the CSRF cookie duck-auth set on signin, send it back as a header, and the mutation succeeds.
CSRF=$(grep duck-csrf cookies.txt | awk '{print $7}')
curl -b cookies.txt -X PATCH http://localhost:3100/companies/company-acme \
  -H 'content-type: application/json' -H "x-csrf-token: $CSRF" -d '{"name":"Acme Renamed"}'
```

## Frameworks

| Framework | Adapter | Dir | Port |
|---|---|---|---|
| Express | `@gentleduck/iam/server/express` | `express/` | 3100 |
| Hono | `@gentleduck/iam/server/hono` | `hono/` | 3200 |
| NestJS | `@gentleduck/iam/server/nest` | `nest/` | 3300 |
| Next.js | `@gentleduck/iam/server/next` + `@gentleduck/auth/server/next` (routes) — `@gentleduck/iam/client/react` + `@gentleduck/auth/client/react` (dashboard) | `next/` | 3400 |

Next.js is the odd one out by design: it's the one framework where API routes and React pages
already live in one app, so its `src/app/dashboard` page is where both client adapters get
exercised — real sign-in/sign-up forms (`useSignIn`, `useAuthClient().signUp`) gating a real
`<AccessProvider>` tree, no separate client project for it to belong to. Express, Hono, and
NestJS stay API-only; exercise their auth routes with curl (see the per-backend CSRF example
above) or point any HTTP client at them.

Each framework directory is backend-only (`src/`, no `backend/` subfolder) and owns only what's
actually per-framework: routing, the adapter wiring, its own `pg.Pool`. Run any one with
`cp .env.example .env && bun run db:setup && bun run dev` from inside its directory (only one
framework needs to run `db:setup` — every process migrates and seeds the same shared database).

See `TODO.md` for the build/verification checklist.
