# duck-auth-demo

End-to-end demo for `@gentleduck/auth`:

- **Hono backend** + **Drizzle / Postgres** with every auth flow wired
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

| Flow | Endpoint(s) | Status |
|------|-------------|--------|
| Password | `POST /auth/signin` (provider `password`) | always on |
| Magic-link | `POST /auth/providers/magic-link/begin` then `GET /auth/magic-link/verify?token=…` | always on (link printed to console + `/__dev/outbox`) |
| Google OAuth | `POST /auth/providers/google/begin` + `GET /auth/providers/google/callback` | requires `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET` |
| GitHub OAuth | `POST /auth/providers/github/begin` + `GET /auth/providers/github/callback` | requires `GITHUB_CLIENT_ID` + `GITHUB_CLIENT_SECRET` |
| Passkey enroll | `POST /auth/passkey/registration/{begin,finish}` | always on |
| Passkey sign-in | `POST /auth/passkey/authentication/{begin,finish}` | always on |
| TOTP enroll | `POST /auth/mfa/totp/begin` + `POST /auth/mfa/totp/confirm` | always on |
| TOTP verify | `POST /auth/mfa/totp/verify` | always on |
| Backup codes | `POST /auth/mfa/backup-codes/regenerate` | always on |
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
  └── auth-layout.tsx         + .stories.tsx
```

Each component has both **mocked** stories (using the `withAuth` decorator
from `@gentleduck/auth/client/react/storybook` with a fake client) and a
**Live** story that hits the real backend at `:8787`.

## Reset

```sh
bun run db:down   # removes the container + the volume
bun run db:up
bun run db:migrate
```
