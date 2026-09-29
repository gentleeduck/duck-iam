# duck-auth-demo

End-to-end demo for `@gentleduck/auth`:

- **Hono backend** + **Drizzle / Postgres**, its own routes over `auth.flows`
- **Storybook** + ready-made auth UI built on `@gentleduck/registry-ui`
- One launcher (`bun run all`) brings the whole stack up

## Run it

```sh
# Boot everything (postgres + backend + storybook)
bun run all

# -> backend     http://localhost:8787
# -> storybook   http://localhost:6006
```

Or run the pieces separately:

```sh
bun run db:up         # postgres in Docker on :5433
bun run db:migrate    # apply the duck-auth schema
bun run dev           # backend on :8787 (--hot)
bun run storybook     # storybook on :6006
```

The Postgres container is `duck-auth-demo-pg` listening on **localhost:5433**
(non-standard port to avoid colliding with a host Postgres). Data persists in
the `duck-auth-demo-pgdata` volume; `bun run db:down` removes both.

## What's wired

Every route is `src/server.ts`'s own. All but the OAuth callback and the magic-link
link are CSRF-guarded with `honoCsrf`.

| Flow | Endpoint(s) | Status |
|------|-------------|--------|
| Password | `POST /auth/signin` (provider `password`) | always on |
| Magic-link | `POST /auth/providers/magic-link/begin` then `GET /auth/magic-link/verify?token=…` | always on (link printed to console) |
| Google OAuth | `POST /auth/providers/oauth:google/begin` + `GET /auth/providers/oauth:google/callback` | requires `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET` |
| GitHub OAuth | `POST /auth/providers/oauth:github/begin` + `GET /auth/providers/oauth:github/callback` | requires `GITHUB_CLIENT_ID` + `GITHUB_CLIENT_SECRET` |
| Passkey | `POST /auth/providers/passkey/begin` then `POST /auth/signin` (provider `passkey`) | always on |
| Session | `GET /auth/session` | always on |
| Sign-out | `POST /auth/signout` | always on |

## Storybook layout

```
.storybook/             # main, preview, tailwind config
src/ui/                 # React auth components (built on @gentleduck/registry-ui)
  ├── sign-in-form.tsx        + .stories.tsx
  ├── sign-out-button.tsx     + .stories.tsx
  ├── session-badge.tsx       + .stories.tsx
  ├── providers-list.tsx      + .stories.tsx
  ├── mfa-totp-challenge.tsx  + .stories.tsx
  ├── auth-layout.tsx         + .stories.tsx
  └── live.ts                 # the Live stories' fetch calls
```

Each component takes callbacks (`onSubmit`, `onSignOut`, `onSelect`) rather than
reaching for a client, so its **mocked** stories pass stand-ins and its **Live**
story passes `src/ui/live.ts`, plain `fetch` calls to the real backend at `:8787`.

## Reset

```sh
bun run db:down   # removes the container + the volume
bun run db:up
bun run db:migrate
```
