---
'@gentleduck/auth': minor
'@gentleduck/iam': patch
---

**@gentleduck/auth**: end-to-end input + tenant + config-time hardening sweep.

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
