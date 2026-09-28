# duck-auth examples: build checklist

## Shared

- [x] `shared/`: schema re-export, `buildAuth(db)`, seed, `createDb()`, body narrowing,
      `signedIn()`. `drizzle/` is the one migration history.
- [x] `shared/`: `signUp()` and `stepUp()`, so all eight backends sign up and step up alike. Sign-up
      refuses a malformed email or an empty or overlong name, and erases the new identity when its
      password cannot be stored. Step-up revokes the one-factor session its cookie replaced.
- [x] `ui/`: `createApi(base)`, backend map + Vite proxy, duck-ui recipes and theme.

## Backends

Each backend has `src/db/{index,migrate,seed}.ts`, mounts duck-auth's own handlers, and writes the
app routes (see the route table in `README.md`) with its framework's router, CSRF guard and
error handler.

- [x] express, hono, fastify, koa, elysia, nest, bun, next: `tsc` + biome clean. The API smoke
      passes against each one (fails=0): sign-in, sign-up, verify, reset, magic link, TOTP
      enrol/step-up/backup codes/remove, sessions, revoke-others, sign-out, unknown callback.
- [x] A malformed or oversize JSON body answers 400 on express, fastify and koa, as it does on hono,
      bun and next: each reads it as no body, the way duck-auth's `readBodyJson` does. Elysia parses
      its own body, so Bun caps it at the same 100 KiB (413); nest answers its own 413.
- [x] A body that is not a sign-in answers `AUTH_INVALID_CREDENTIALS` 400 on every backend, bun's
      hand-written routes included, as the adapters do.
- [x] An IdP callback lands on `APP_URL` once signed in, and on `/sign-in?error=CODE` otherwise, on
      all eight: `landing()` in `shared/` covers both the error intents and the thrown `AuthError`s
      (a forged `state`, an IdP refusal).
- [x] OAuth makes an account for a first-time IdP user and links an existing one only when both
      sides verified the address. A provider turns on only once its id and secret are both set.
- [x] Rate limits are duck-auth's default, ten tries per account and flow every 15 minutes, on all
      eight: the 11th wrong password answers `AUTH_RATE_LIMITED` with `retryAfter: 900`.
- [x] `GET /me` and `GET /me/sessions` answer `cache-control: no-store` on all eight, as duck-auth's
      own session route does. Express and nest do not send `X-Powered-By`.
- [x] A spoofed `x-forwarded-for` does not reach a session's recorded address on any backend.
- [x] grpc: `bun run client` signs in, reads the account back, and signs out. `VerifyMfa` revokes
      the one-factor token it replaces, as `stepUp()` does for a cookie.
- [x] The README's quick start works from an empty database. A backend pointed at a database never
      migrated answers `AUTH_MISCONFIGURED` and names the missing table in its terminal.
- [x] next: its own Playwright run passes. `next build` is refused by design (see "Development
      only" in `README.md`).

## Clients

Pages: sign-in, sign-up, forgot-password, reset-password, verify-email, magic-link, mfa, and the
dashboard.

- [x] react, vue, svelte, solid, vanilla: type-check (`tsc`, vue-tsc, svelte-check), biome and
      `vite build` all clean. The Playwright run passes against express (fails=0). It covers:
      - `?error=CODE` on the sign-in page, and the fallback for an unknown code;
      - a bad password;
      - TOTP enrolment by a QR code that decodes to the key, step-up and backup codes;
      - a magic link;
      - a weak password on sign-up;
      - email verification;
      - reset, then sign-in with the new password;
      - the same session through a second backend;
      - no console errors.
- [x] react: the same Playwright run passes against hono, fastify, koa, elysia, nest and bun.
- [x] Every client's IdP button reaches the IdP, and a failure shows on the page. On react, a forged
      callback lands back on sign-in with the reason.
- [x] A dashboard sends a step-up to `/mfa`, a guest to `/sign-in`, and anything else to
      `/sign-in?error=CODE`, so a backend fault is not shown as being signed out.
- [x] The Sessions card lists every signed-in device, newest first, with when and where it signed
      in, and marks this one. The Playwright run checks the mark on every client and the Next app.
- [x] `AUTH_INVALID_PARAMETERS` and `AUTH_RECOVERY_REQUIRES_MFA` have their own messages. A rate
      limit says how many minutes are left.
- [x] A form takes one submit at a time, so a double click sends one email. The Playwright run
      checks both on every client and the Next app.
- [x] A dashboard button is disabled while its call is out, so a double click begins one TOTP setup
      and "Sign out other devices" reports the devices it signed out, on every client and Next.
- [x] A page whose session another device signed out goes to `/sign-in` on its next call.
- [x] A magic link opened in another browser signs that browser in; a second use says why not.
- [x] Every page has one `<h1>`, and axe (WCAG 2 A/AA, best practice) finds nothing on any page of
      any client.
- [x] Every page has its own title, as "Sign in · duck-auth · React", and none scrolls sideways at
      phone width (375px), on every client and Next.

## Found in duck-auth while building these

Fixed in duck-auth (`audit-auth/FINDINGS.md` #350-#362), and the examples use the fix:

- [x] The vanilla client labelled a bodiless POST as JSON, so stock Fastify refused every sign-out.
- [x] Express `applyIntents` answered an `error` intent outside the `{ ok: false, error }` envelope.
- [x] Koa had no intents writer for a host route. `koa/` uses `koaApplyIntents`.
- [x] `ExpressAdapter.Request.params` refused Express 5's `string | string[]` params.
- [x] React's `useSignUp` required a `username` and ignored `path`. `react/` uses `useSignUp`.
- [x] `withNextCsrf` dropped the route's `{ params }`.
- [x] `profileToIdentityProfile` could not return `null` to refuse a first sign-in. `shared/` refuses
      an IdP profile with no email that way.
- [x] `sessions.listForIdentity` listed expired sessions, and `revokeAllExcept` counted them. The
      Sessions card lists and signs out only live ones.
- [x] Sessions never slid, so an active user was signed out a week after signing in. The Sessions
      card's "ends" date now moves once less than half the week is left.
- [x] Signing in again in the same browser left the first session live, so the Sessions card listed
      one browser twice. The sign-in now ends it; bun's own sign-in route passes the cookie's SID too.
- [x] A 5xx left the backend's terminal empty, though the page says the terminal holds the reason.
      Every backend now leaves logging it to `errorToHttp`.

Reported to duck-auth, and handled here:

- `completeStepUp` keeps the one-factor session live for a tab still holding it. A cookie leaves no
  such tab, so `stepUp()` revokes it.
- `mfa.removeTotp` keeps the backup codes. Every backend's `/auth/mfa/totp/remove` removes them too.

By design:

- Every client and server export resolves to `dist/`, so the examples need `bun run build` in
  `packages/duck-auth` first.
- `oauthCallback` sets the session cookies but does not redirect: where the browser lands is the
  app's call. Every backend wraps it in `landing()`.
- An OAuth provider with no `profileToIdentityProfile` refuses every first sign-in: the app's
  profile shape is the app's to make.
