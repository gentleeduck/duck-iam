# duck-auth examples

Nine backends, one per `@gentleduck/auth` server adapter, and five browser clients. They all use
one shared Postgres database, so an account made on one backend can sign in on any other, and one
browser session works against all of them.

duck-auth has no routes and no client. It provides the flows (`auth.flows.*`) and, per framework,
the CSRF guard, the actor scope and the caller fingerprint. Each backend writes every route itself,
the way an app would, and each client calls them with `fetch`.

## Quick start

From the repo root:

```sh
bun install
(cd packages/duck-auth && bun run build)   # every example imports duck-auth from dist/

# A Postgres matching every .env.example. Already running one? Point DATABASE_URL at it instead.
docker run -d --name duck-auth-examples-pg -p 5432:5432 -e POSTGRES_USER=iryss \
  -e POSTGRES_PASSWORD=iryss -e POSTGRES_DB=duck_auth_examples postgres:18-alpine

cd examples/duck-auth/express
cp .env.example .env
bun run db:setup                           # migrate and seed, once for every backend
bun run dev                                # http://localhost:4100
```

Then, in a second terminal from the repo root:

```sh
cd examples/duck-auth/react && bun run dev  # http://localhost:5100
```

Sign in as `ada@duck.test` / `duck-auth-examples`.

## Shared packages

- `shared/` (`@examples/duck-auth-shared`), used by every backend:
  - `schema`: duck-auth's pg tables, re-exported so `drizzle-kit generate` finds them.
  - `auth`: `buildAuth(db)` with passwords, TOTP + backup codes, magic links, and GitHub/Google
    once their env is set.
  - `seed`: the demo account.
  - `db`: a `pg.Pool` + drizzle factory.
  - `body`: JSON body narrowing.
  - `session`: `signedIn()`, which refuses a guest, and a one-factor session once TOTP is on;
    `stepUp()`, the second step of a sign-in.
  - `routes`: the framework-free part of sign-in, sign-out, the session and the provider begin and
    callback routes, over `auth.flows.*`.
  - `signup`: `signUp()`, a password account, unverified until its emailed link is opened.
- `ui/` (`@examples/duck-auth-ui`), used by every client:
  - `api`: a `fetch` call for each route the backends answer.
  - `backends`: the port map and the Vite proxy.
  - `recipes`: duck-ui's registry styles as `@gentleduck/variants` recipes.
  - `theme.css`: duck-ui's tokens.

Migrations are generated once, in `shared/`. Every backend's `db:migrate` applies that same
history.

## Database

Any Postgres works. Every `.env.example` points at
`postgresql://iryss:iryss@localhost:5432/duck_auth_examples`, which the quick start's container
provides. Each package reads its own `.env`, copied from its `.env.example`, and `DATABASE_URL`
has no fallback. Run `db:setup` once, from any backend.

## Backends

| Framework | Adapter | Dir | Port |
|---|---|---|---|
| Express | `server/express` | `express/` | 4100 |
| Hono | `server/hono` | `hono/` | 4200 |
| Fastify | `server/fastify` | `fastify/` | 4300 |
| Koa | `server/koa` | `koa/` | 4400 |
| Elysia | `server/elysia` | `elysia/` | 4500 |
| NestJS | `server/nestjs` | `nest/` | 4600 |
| Bun | `server/generic` on `Bun.serve` | `bun/` | 4700 |
| Next.js | `server/next` | `next/` | 4800 |
| gRPC | `server/grpc` | `grpc/` | 4900 |

Every HTTP backend answers the same routes:

- `POST /auth/signin`, `POST /auth/signout`, `GET /auth/session`, `GET /auth/providers`
- `POST /auth/providers/:id/begin`, `GET/POST /auth/providers/:id/callback`
- `POST /auth/signup`, `/auth/password/forgot`, `/auth/password/reset`, `/auth/email/verify`
- `POST /auth/mfa/verify`, `/auth/mfa/totp/{begin,confirm,remove}`, `/auth/mfa/backup-codes`
- `GET /me`, `POST /me/email/resend`, `GET /me/sessions`, `POST /me/sessions/revoke-others`

Every route but the provider callback takes the CSRF guard. The callback is where the IdP sends
the browser back, Apple with a cross-site form post, so the signed `state` is its proof instead.

Next.js is full stack: it serves these routes under `/api` and serves its own pages. gRPC has
no browser client. With the server running, `bun run client` signs the demo account in, reads
it back and signs out. Set `MFA_CODE` once TOTP is on.

## Clients

| Framework | Components | Dir | Port |
|---|---|---|---|
| React | `@gentleduck/registry-ui` | `react/` | 5100 |
| Vue | `ui/` recipes | `vue/` | 5200 |
| Svelte | `ui/` recipes | `svelte/` | 5300 |
| Solid | `ui/` recipes | `solid/` | 5400 |
| Vanilla | `ui/` recipes | `vanilla/` | 5500 |

Each client has the same auth pages and a dashboard home:
- sign in, sign up, forgot and reset password, email verification, magic link, the MFA check;
- a dashboard with the account, TOTP setup and backup codes, and the signed-in devices.

React uses the duck-ui registry components. The other clients style the same markup with the
`ui/` recipes. A picker under each page chooses the backend. The Vite proxy serves every backend
at `/api/<name>` on the client's own origin, so the session cookie carries across them.

## Emailed links

There is no mailer. Each magic-link, reset and verification link is printed in the terminal of
the backend that sent it. `APP_URL` decides which client the link opens (5100, React, by
default). Point it at another client's port to follow links there.

## OAuth

GitHub and Google turn on once both `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`, or
`GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`, are set. Register
`${API_URL}/auth/providers/oauth:<id>/callback` with the provider.

After the callback, the backend redirects to `APP_URL`. A failed sign-in lands on the sign-in
page instead, with `?error=CODE`, which the page shows. A first-time IdP user gets an account
under the address the IdP returns. An existing account with that address is linked only when both
it and the IdP verified the address (`onFederationConflict: 'link-if-verified'`).

## Development only

These examples use the in-memory rate limiter and DPoP nonce store. duck-auth refuses both
under `NODE_ENV=production`, which is why the Next.js example has no `build` script.

See `TODO.md` for the build and verification checklist.
