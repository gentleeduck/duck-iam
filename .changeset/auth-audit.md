---
'@gentleduck/auth': minor
---

**BREAKING: duck-auth ships no routes and no browser client.** The sign-in, sign-out,
session and provider begin and callback handlers are gone from every server adapter
(`mountSignIn`, `honoSignIn`, `fastifySignIn`, `nestSignIn` and the rest), with `mountHono`
and its magic-link, passkey and MFA routes, `mountNext`, `registerFastify`, and `server/generic`'s
`oauthCallback`, `parseSignInBody` and `parseProviderBeginBody`. So are the five client bindings, `@gentleduck/auth/client/vanilla`,
`/react` (with `/react/storybook`), `/vue`, `/svelte` and `/solid`, with `createAuthClient`,
`Envelope` and the `react`, `vue` and `solid-js` peers. Your app writes its routes over
`auth.flows.*`, and its pages call them with `fetch`. The adapters keep the glue: the CSRF
guard, the caller fingerprint, `applyIntents` and `executeIntents`, the actor context, the error
helpers, and Nest's guards, filter and decorators; `NestExceptionFilter` now also sets
`Cache-Control: no-store`. What the handlers did, your routes now must:

- CSRF-guard sign-in, sign-out, begin and every other write. Only the OAuth callback stays
  unguarded, since the IdP's page posts it cross-site, so it must drive only a provider of kind
  `oauth`.
- On the callback, read the query on GET and the urlencoded body as text on POST, and pass
  `code`, `state`, Apple's `user` field and the request's `cookie` header as `cookieHeader`.
- Pass `previousSid: auth.transport.extract(req) ?? undefined` and the adapter's caller to
  `flows.signIn`, so signing in again ends the previous session.
- Strip `csrfHash` from any session you answer, and answer with `Cache-Control: no-store`, which
  `executeIntents`, `applyIntents` and `jsonResponse` set.
- Answer a begin a script calls with `{ url }` when `isSafeRedirectUrl` accepts the redirect:
  `fetch` cannot follow it to the IdP.
- Require `checkStepUp` at AAL 2 before removing a TOTP factor or regenerating backup codes,
  rate-limit `stepup:${identityId}` on any route that verifies a TOTP code, and pass the session's
  tenant to every `auth.mfa` call.
- Nest's `onAuthenticated` hook went with its handler: check the new session in your route before
  applying the intents, and call `flows.signOut(sid)` to refuse it.

`examples/duck-auth` writes these routes on every framework.
