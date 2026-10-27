# Test map: duck-auth (@gentleduck/auth)

Generated 2026-10-21 by `benchmark/scripts/map.ts`. Do not hand-edit.

**282 test files, 3712 statically counted cases.** Static counting is a lower bound — see `benchmark/README.md`.

| Cluster | Files | Tests |
| --- | --- | --- |
| [Anomaly detection, device fingerprint, impossible travel, hijack](#anomaly) | 5 | 144 |
| [Encryption at rest (AES-GCM, KMS envelope)](#data-at-rest) | 6 | 92 |
| [Webhooks + event delivery / audit bus](#webhooks-events) | 14 | 214 |
| [Idempotency keys](#idempotency) | 6 | 68 |
| [Multi-tenancy scoping](#tenancy) | 10 | 79 |
| [Machine-to-machine grants](#m2m) | 3 | 57 |
| [Compliance presets + capability matrix](#compliance-presets) | 1 | 37 |
| [Server framework adapters (hono/express/fastify/koa/elysia/nest/next/grpc)](#frameworks-server) | 18 | 183 |
| [SAML + SSO provider registry](#saml-sso) | 8 | 126 |
| [OIDC provider (authorize/token/DCR/introspect/resources)](#oidc-op) | 11 | 175 |
| [Transport: cookies, bearer, JWT, DPoP, CSRF, origin](#transport) | 17 | 287 |
| [OAuth2 client + social providers](#oauth-social) | 9 | 138 |
| [Passkey / WebAuthn](#passkey) | 7 | 107 |
| [MFA: TOTP, backup codes, step-up](#mfa) | 20 | 183 |
| [API keys](#api-key) | 7 | 66 |
| [Organizations, teams, members, invites, access control](#orgs) | 5 | 67 |
| [Admin / impersonation / actor context](#admin-actor) | 4 | 39 |
| [Sessions (lifetime, revocation, refresh, multi-session)](#sessions) | 18 | 268 |
| [Password hashing, rehash, rotation, pwned checks](#passwords) | 13 | 135 |
| [Magic link, email verification, one-time tokens](#magic-link) | 7 | 131 |
| [Rate limiting / brute-force / lockout](#rate-limit) | 6 | 48 |
| [CAPTCHA](#captcha) | 3 | 58 |
| [Store adapters + schema/migration layer](#adapters) | 24 | 210 |
| [Engine, config, context, flows, identities, errors, utils](#engine-config) | 60 | 800 |

## anomaly

Anomaly detection, device fingerprint, impossible travel, hijack — 5 files, 144 tests, scope `duck-only`.

| Tests | File | Suites |
| --- | --- | --- |
| 45 | `core/anomaly/__tests__/anomaly.test.ts` | construction refuses a ladder that would fail open; the registry; the aggregate saturates, so neither count nor sign can steer it (+5) |
| 43 | `core/hijack/__tests__/hijack-policy.test.ts` | a request that matches the session is let through; a changed value is drift; when both signals fire, the stronger reaction wins (+9) |
| 31 | `core/anomaly/__tests__/device-fingerprint.test.ts` | first sight; the address is reduced to the network it came from; a device is remembered only once the verdict lets it through (+4) |
| 20 | `core/anomaly/__tests__/impossible-travel.test.ts` | a hop too fast to be travel; the minimum interval is a floor, not an exemption; what the detector has nothing to say about (+1) |
| 5 | `core/anomaly/__tests__/anomaly.pg.e2e.test.ts` **[env-gated]** |  |

## data-at-rest

Encryption at rest (AES-GCM, KMS envelope) — 6 files, 92 tests, scope `duck-only`.

| Tests | File | Suites |
| --- | --- | --- |
| 40 | `core/dataAtRest/__tests__/aes-gcm-nonce.test.ts` | the IV is fresh for every encryption; equal plaintexts do not produce equal ciphertexts; the context separates keys (+5) |
| 20 | `core/dataAtRest/__tests__/kms-envelope-edge.test.ts` | AuthKmsEnvelopeDataAtRest - edge cases; AuthKmsEnvelopeDataAtRest - GCM parameter sizes; AuthKmsEnvelopeDataAtRest - input bounds, checked before KMS is called |
| 11 | `core/dataAtRest/__tests__/aes-gcm-hardening.test.ts` | AuthAesGcmDataAtRest - decrypt hardening; AuthAesGcmDataAtRest - kid cannot collide with the field separator |
| 10 | `core/dataAtRest/__tests__/aes-gcm.test.ts` | AuthAesGcmDataAtRest |
| 6 | `core/dataAtRest/__tests__/kms-envelope.test.ts` | AuthKmsEnvelopeDataAtRest |
| 5 | `core/dataAtRest/__tests__/aws-kms.test.ts` | AuthAwsKmsProvider (with mocked @aws-sdk/client-kms) |

## webhooks-events

Webhooks + event delivery / audit bus — 14 files, 214 tests, scope `duck-only`.

| Tests | File | Suites |
| --- | --- | --- |
| 77 | `core/webhooks/__tests__/webhooks-delivery.test.ts` | the ssrf guard is a deny-list over the written form of the host; delivery runs inside the emit, so its latency is the caller’s; the retry loop cannot tell a transient failure from a permanent one (+2) |
| 26 | `core/events/__tests__/events.delivery.test.ts` | RedisEvents delivery; InMemoryEvents delivery; the wrappers pass the delivery through (+1) |
| 19 | `core/events/__tests__/events.redis.test.ts` | RedisEvents; pub/sub envelope validation (hostile publisher defense); RedisEvents subscribes to each channel once (+2) |
| 18 | `core/events/__tests__/resubscribe-race.test.ts` | RedisEvents: swapping the last handler must not leave the channel closed; RedisEvents on valkey: origin handlers hold no channel; RedisEvents: a subscribe that failed is retried until it lands |
| 15 | `core/webhooks/__tests__/webhooks.test.ts` | AuthWebhookDeliverer |
| 14 | `core/events/__tests__/lockout.test.ts` | refuseRateLimited; lockout is emitted where the refusal knows whose account it is; lockout is withheld where the refusal has no subject |
| 10 | `core/events/__tests__/events.audit.test.ts` | withAuditStamping; auditEnvelopeFor |
| 7 | `core/events/__tests__/audit-actor.test.ts` | audited events carry the operator; an erasure reaches the audit log with its operator |
| 6 | `core/events/__tests__/events.redis-dates.test.ts` | RedisEvents payload dates survive the fan-out |
| 6 | `core/webhooks/__tests__/config-bounds.test.ts` | WebhookDeliverer refuses a config that would silently never deliver |
| 5 | `core/events/__tests__/events.redis.e2e.test.ts` **[env-gated]** |  |
| 4 | `core/events/__tests__/events.delivery.e2e.test.ts` **[env-gated]** |  |
| 4 | `core/webhooks/__tests__/webhooks-origin.test.ts` | WebhookDeliverer.attach on a fleet |
| 3 | `core/events/__tests__/events.valkey.e2e.test.ts` **[env-gated]** |  |

## idempotency

Idempotency keys — 6 files, 68 tests, scope `duck-only`.

| Tests | File | Suites |
| --- | --- | --- |
| 22 | `core/idempotency/__tests__/idempotency.memory.test.ts` | MemoryIdempotencyStore; IdempotencyFacet.handle; the facet windows |
| 19 | `core/idempotency/__tests__/idempotency.redis-parser.test.ts` | RedisIdempotencyStore.get - parser hardening; malformed JSON; non-object JSON values (the `null.status` crash class) (+3) |
| 10 | `core/idempotency/__tests__/executor-failure.test.ts` | IdempotencyImpl release failures and the poll loop |
| 8 | `core/idempotency/__tests__/idempotency.redis.test.ts` | RedisIdempotencyStore |
| 7 | `core/idempotency/__tests__/idempotency.redis.e2e.test.ts` **[env-gated]** |  |
| 2 | `core/idempotency/__tests__/idempotency.valkey.e2e.test.ts` **[env-gated]** |  |

## tenancy

Multi-tenancy scoping — 10 files, 79 tests, scope `duck-only`.

| Tests | File | Suites |
| --- | --- | --- |
| 30 | `core/tenant/__tests__/tenant.test.ts` | withTenant establishes a scope; the scope survives asynchrony; concurrent scopes do not bleed into each other (+4) |
| 9 | `core/identities/__tests__/export-tenant-scope.test.ts` |  |
| 8 | `core/sessions/__tests__/sessions-tenant-scope.test.ts` | D4 - sessions are tenant-scopable; D4 - the Redis store keeps its index reachable after a scoped sweep |
| 7 | `core/__tests__/tenant.test.ts` | authWithTenant / authCurrentTenant / authResolveTenant |
| 6 | `adapters/memory/__tests__/find-by-hashed-secret-tenant.test.ts` | MemoryAdapter.findByHashedSecret - tenant filter parity with SQL adapter |
| 5 | `core/flows/__tests__/flows-password-reset-tenant.test.ts` | completePasswordReset writes the new password into the tenant it was asked for; a new password the policy refuses spends nothing; a password reset revokes every remembered device |
| 5 | `core/flows/__tests__/flows-stepup-tenant-binding.test.ts` | completeStepUp binds the factor to the session it is stepping up |
| 4 | `core/__tests__/resolve-session-tenant.test.ts` | AuthEngine.resolveSession - SEC: cross-tenant access guard |
| 4 | `core/orgs/__tests__/orgs-tenant-forwarding.test.ts` | OrgsImpl forwards the tenant context it was given |
| 1 | `adapters/memory/__tests__/identities-global-tenant.test.ts` | identities store is tenant-free (global account) |

## m2m

Machine-to-machine grants — 3 files, 57 tests, scope `duck-only`.

| Tests | File | Suites |
| --- | --- | --- |
| 35 | `core/m2m/__tests__/m2m-grant.test.ts` | m2m client_credentials; the tenant the token speaks for; the scopes the token carries (+4) |
| 14 | `core/m2m/__tests__/m2m.test.ts` | M2MFacet - client_credentials grant |
| 8 | `core/m2m/__tests__/m2m-brute-force.test.ts` | the client_credentials grant is bounded; the inputs reach the hash and the limiter key as strings or not at all; the grant is reachable from outside the package |

## compliance-presets

Compliance presets + capability matrix — 1 files, 37 tests, scope `duck-only`.

| Tests | File | Suites |
| --- | --- | --- |
| 37 | `core/compliance/__tests__/compliance-presets.test.ts` | what a preset declares against what is enforced; the resolved overrides are shared, mutable objects; applying a preset to an engine config (+2) |

## frameworks-server

Server framework adapters (hono/express/fastify/koa/elysia/nest/next/grpc) — 18 files, 183 tests, scope `duck-only`.

> better-auth has one handler for every framework, so it has nothing per-framework to test.

| Tests | File | Suites |
| --- | --- | --- |
| 30 | `server/__tests__/request-security.test.ts` | the fingerprint check is off until an adapter is given a getCaller; a supplied getCaller reaches the hijack policy; a device is remembered only once the request is let through (+6) |
| 28 | `server/generic/__tests__/generic.test.ts` | isSafeRedirectUrl; serializeCookie - header injection guards; executeIntents refusing an unsafe redirect (+2) |
| 22 | `server/__tests__/actor-context.frameworks.e2e.test.ts` | Hono, with honoActorContext above the routes; Nest, with nestActorContext applied to every route; gRPC, with withGrpc around a unary handler (+4) |
| 16 | `server/__tests__/actor-context.test.ts` | the adapters bind an actor scope around handler execution; a request is attributed to its own session, never to the scope it arrived in; impersonation attributes the operator, not the account acted on (+3) |
| 14 | `server/nestjs/__tests__/nestjs.test.ts` | NestJS adapter - makeGuard; NestJS adapter - the Nest slot each export is documented for; NestJS adapter - CSRF (+2) |
| 9 | `server/__tests__/caller-context.test.ts` | callerContext; what reaches the session row |
| 9 | `server/express/__tests__/express.test.ts` | toHeaders; applyIntents; a stock Express 5 app (+1) |
| 8 | `server/__tests__/adapters-caller.test.ts` | adapters read the caller their framework resolved |
| 8 | `server/nestjs/__tests__/guard-csrf-parity.test.ts` | nestjs makeGuard reaches the same CSRF verdict as makeCsrfGuard; makeGuard and a bearer on another scheme |
| 7 | `server/grpc/__tests__/grpc.test.ts` | httpStatusToGrpc; withGrpc |
| 5 | `server/grpc/__tests__/grpc-request-security.test.ts` | grpc request security |
| 5 | `server/hono/__tests__/hono.test.ts` | honoCsrf; toHonoAdapterCtx |
| 5 | `server/koa/__tests__/koa.test.ts` | koaCsrf; koaApplyIntents |
| 5 | `server/next/__tests__/next.test.ts` | withNextCsrf |
| 4 | `server/elysia/__tests__/elysia.test.ts` | elysiaCsrf |
| 4 | `server/fastify/__tests__/fastify.test.ts` | fastifyCsrf |
| 2 | `server/__tests__/adapter-options-wired.test.ts` | every adapter option a host can set is read by an adapter |
| 2 | `server/nestjs/__tests__/nestjs.e2e.test.ts` |  |

## saml-sso

SAML + SSO provider registry — 8 files, 126 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 29 | `providers/saml/__tests__/saml-metadata-xsd-shape.test.ts` | SAML 2.0 metadata XML - XML well-formedness; SAML 2.0 metadata XSD §2.4 - required EntityDescriptor attributes; SAML 2.0 metadata XSD §2.4 - AssertionConsumerService (+6) |
| 28 | `providers/saml/__tests__/saml-binding.test.ts` | what ties a response to the request that started it; the assurance level the session is given; the profile the IdP asserts (+2) |
| 19 | `providers/saml/__tests__/saml-metadata-and-slo.test.ts` | buildSpMetadata; samlSloController.beginSp; samlSloController.completeSp (+1) |
| 17 | `providers/saml/__tests__/saml-hardening.test.ts` | samlProvider - input caps; begin; complete - SAMLResponse cap (+2) |
| 13 | `providers/saml/__tests__/saml-node-saml.test.ts` | sign-in through a real node-saml client; IdP-initiated logout through a real node-saml client; Redirect-binding logout through a real node-saml client |
| 10 | `providers/saml/__tests__/saml.test.ts` | samlProvider - construction guards; samlProvider - begin; samlProvider - complete |
| 6 | `providers/saml/__tests__/saml-nameid-format-scope.test.ts` | the email/nameID agreement check |
| 4 | `providers/saml/__tests__/saml-unsigned-client.test.ts` | samlProvider refuses a client that verifies no signature at all |

## oidc-op

OIDC provider (authorize/token/DCR/introspect/resources) — 11 files, 175 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 35 | `oidc/__tests__/oidc.test.ts` | authBuildOidcDiscovery; authBuildOidcRoutes; authFetchOidcDiscovery - RP-side cache (+3) |
| 32 | `oidc/op/__tests__/op.test.ts` | AuthOidcOpRoot.registerClient; AuthOidcOpRoot.authorize gate; AuthOidcOpRoot end-to-end code flow (+2) |
| 29 | `oidc/__tests__/rfc-conformance.test.ts` | RFC 8414 §2 + OIDC Discovery §4 - required claims; oauth 2.0 PKCE (RFC 7636) - code_challenge_methods_supported; id_token signing algs - real-RP expectations (+4) |
| 22 | `oidc/op/__tests__/dcr.test.ts` | AuthOidcOpRoot.register (RFC 7591 DCR); when DCR is disabled (default); with open registration (+3) |
| 21 | `oidc/op/__tests__/op-security.pg.e2e.test.ts` **[env-gated]** | the authorization code is bound to its client; the authorization code is bound to its redirect_uri; PKCE (+4) |
| 18 | `oidc/op/__tests__/rfc-token-conformance.test.ts` | RFC 6749 §5.1 - successful token response shape; RFC 6749 §5.2 - error response shape; RFC 6749 §3.1.2 - authorize redirect format (+1) |
| 12 | `oidc/op/drizzle/__tests__/contract.test.ts` | pg dialect surface; mysql dialect surface; sqlite dialect surface (+1) |
| 3 | `oidc/op/drizzle/__tests__/mysql-driver-shape.test.ts` | the write count each mysql driver answers with |
| 1 | `oidc/op/drizzle/__tests__/oidc-op.mysql.e2e.test.ts` **[env-gated]** | authGcDrizzleMysqlOidcOp |
| 1 | `oidc/op/drizzle/__tests__/oidc-op.pg.e2e.test.ts` **[env-gated]** | authGcDrizzlePgOidcOp |
| 1 | `oidc/op/drizzle/__tests__/sqlite.test.ts` | DrizzleSqlite OIDC OP stores; authGcDrizzleSqliteOidcOp |

## transport

Transport: cookies, bearer, JWT, DPoP, CSRF, origin — 17 files, 287 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 43 | `core/transport/__tests__/dpop.test.ts` | AuthDPoPVerifier; authComputeJwkThumbprint; authBindPayloadToDPoP (+5) |
| 42 | `core/transport/__tests__/composite.test.ts` | construction; extract resolves a request carrying two credentials by array order; verify accepts a token any one transport will vouch for (+3) |
| 40 | `core/transport/__tests__/jwt.test.ts` | JwtTransport; issue + verify roundtrip; extract (+9) |
| 29 | `core/transport/__tests__/cookie.test.ts` | AuthCookieTransport - construction invariants; AuthCookieTransport.extract - happy path; AuthCookieTransport.extract - SEC: hardened parser (+1) |
| 23 | `core/__tests__/csrf.test.ts` | CSRF; authIssueCsrfToken / authBuildCsrfCookieOptions; authVerifyCsrf - safe methods + bearer exemption (+5) |
| 20 | `core/__tests__/csrf-hardening.test.ts` | CSRF - header-token length cap; CSRF - authCsrfGuard bearer-scheme detection; CSRF - a bearer header does not disarm the cross-site gate |
| 19 | `core/transport/__tests__/jwt-asymmetric.test.ts` | JwtTransport - ES256; JwtTransport - RS256; JwtTransport - alg-confusion guard (RFC 8725 section 3.1) (+4) |
| 17 | `core/transport/__tests__/bearer.test.ts` | AuthBearerTransport.extract; hardened scheme matching + multi-header defense; custom scheme/header config (+2) |
| 12 | `core/engine/__tests__/transport-verdict-survives.test.ts` | a transport verdict survives the store fallthrough; a composite hands its members verdict up; an authoritative refusal through the engine |
| 9 | `core/csrf/__tests__/bearer-autodetect.test.ts` | verifyCsrf derives the bearer exemption from the Authorization header; a bearer configured on another header or scheme |
| 7 | `core/transport/__tests__/csrf-companion-cookie.test.ts` | the CSRF companion is scoped to the session cookie |
| 7 | `core/transport/__tests__/jwt-rotation-stress.test.ts` | JwtTransport - rotation under concurrent issue |
| 6 | `core/transport/__tests__/jwt-verify-length-cap.test.ts` | JwtTransport.verify - length cap; AuthCompositeTransport.verify - length cap |
| 5 | `core/transport/__tests__/dpop-nonce.redis.e2e.test.ts` **[env-gated]** |  |
| 3 | `core/transport/__tests__/dpop-nonce.redis.test.ts` | RedisDPoPNonceStore |
| 3 | `core/transport/__tests__/jwt-freshness-clock-skew.test.ts` | freshness is bounded in both directions |
| 2 | `core/transport/__tests__/dpop-nonce.valkey.e2e.test.ts` **[env-gated]** |  |

## oauth-social

OAuth2 client + social providers — 9 files, 138 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 54 | `providers/oauth/__tests__/oauth.test.ts` | oauth core - PKCE + state; authVerifyState - SEC: payload validation; OAuthClient - SEC: token response validation (+4) |
| 27 | `providers/oauth/core/__tests__/state.test.ts` | a state the library signed comes back intact; anything the library did not sign is refused; shapes that are not a state at all (+4) |
| 15 | `providers/oauth/github/__tests__/github.test.ts` | github provider - its token endpoint and API as GitHub answers them; github provider - profile resolution; github provider - when /user/emails is unavailable (+1) |
| 11 | `providers/oauth/__tests__/federation-conflict.test.ts` | federation conflict policy, through a shipped provider; Microsoft does not assert an email is verified; Apple does not read an absent email_verified as verified |
| 11 | `providers/oauth/apple/__tests__/apple-id-token-decode.test.ts` | apple authDecodeIdToken - claim-shape validation |
| 9 | `providers/oauth/__tests__/userinfo-extractors.test.ts` | getUserinfoString; getUserinfoNumericIdAsString - the GitHub bug; getUserinfoBooleanTrue |
| 5 | `providers/oauth/apple/__tests__/apple-flow.test.ts` | Sign in with Apple, form_post |
| 5 | `providers/oauth/core/__tests__/outbound-redirects.test.ts` | no outbound oauth request follows a redirect off the endpoint that was checked |
| 1 | `providers/oauth/microsoft/__tests__/microsoft.test.ts` | microsoft provider - profile |

## passkey

Passkey / WebAuthn — 7 files, 107 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 41 | `providers/passkey/__tests__/passkey.test.ts` | passkey provider - registration; passkey provider - a credential id already registered; passkey provider - with the real verifier (+6) |
| 29 | `providers/passkey/__tests__/passkey-counter.test.ts` | passkey signature counter; a counter that goes backwards is a clone signal; a counter that moves forward is accepted and remembered (+7) |
| 11 | `providers/passkey/__tests__/passkey.pg.e2e.test.ts` **[env-gated]** | passkey sign-in; WebAuthn MFA |
| 10 | `providers/passkey/__tests__/passkey-exclude-credentials.test.ts` | beginPasskeyRegistration excludes the keys the identity already holds; beginPasskeyRegistration asks for the attestation it was configured for |
| 8 | `providers/passkey/__tests__/passkey-metadata-parser.test.ts` | passkey complete() - metadata parser |
| 5 | `providers/passkey/__tests__/challenge-store.redis.e2e.test.ts` **[env-gated]** |  |
| 3 | `providers/passkey/__tests__/passkey-manage.test.ts` | passkey management |

## mfa

MFA: TOTP, backup codes, step-up — 20 files, 183 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 50 | `providers/mfa/__tests__/mfa.test.ts` | MfaFacet - TOTP; enrollment; beside a WebAuthn factor (+8) |
| 17 | `core/flows/__tests__/flows-stepup-recovery.test.ts` | FlowsImpl - step-up; FlowsImpl - password reset |
| 17 | `providers/mfa/__tests__/totp.test.ts` | base32; authGenerateSecret + buildOtpAuthUri; totpAt (+3) |
| 14 | `providers/mfa/__tests__/mfa-credential-expiry.test.ts` | MfaImpl honours a credential expiry; totp; webauthn-mfa |
| 14 | `providers/mfa/__tests__/mfa.remember-me.test.ts` | RememberMeFacet; a remembered device goes with the factor it skipped |
| 8 | `providers/mfa/__tests__/backup-code-config-bounds.test.ts` | MfaImpl refuses a backup-code shape that is not a secret; MfaImpl draws every backup-code character with equal odds; RememberMeFacet mints a token that skips the factor for ninety days |
| 8 | `providers/mfa/__tests__/mfa-recovery-purpose.test.ts` | recovery-kind overload; minting and removing codes does not touch the other five; the other five are not second factors (+1) |
| 6 | `providers/mfa/__tests__/backup-code-escalation-event.test.ts` | spending a backup code reaches the bus |
| 6 | `providers/mfa/__tests__/mfa-confirmed-cast.test.ts` | MfaFacet.verifyTotp / hasTotp - confirmed flag |
| 6 | `providers/mfa/__tests__/mfa.backup-codes.test.ts` | MfaImpl backup codes; a backup code through completeStepUp |
| 6 | `providers/mfa/__tests__/remember-me-revoke-purpose.test.ts` | RememberMeFacet.revoke only touches trusted devices; RememberMeFacet list and revokeAll agree about what a device is |
| 6 | `providers/mfa/__tests__/totp-reenroll-destroys-factor.test.ts` | MfaFacet - re-enrolling TOTP over a confirmed factor |
| 5 | `providers/mfa/__tests__/totp-empty-secret.test.ts` | a TOTP secret that decodes to no bytes verifies nothing |
| 4 | `core/flows/__tests__/flows-stepup-rate-limit.test.ts` | completeStepUp is rate limited |
| 4 | `providers/mfa/__tests__/otpauth-uri-encoding.test.ts` | the otpauth URI says what the issuer is called |
| 3 | `core/flows/__tests__/flows-require-mfa-intent.test.ts` | a requireMfa intent is acted on, not dropped |
| 3 | `providers/mfa/__tests__/backup-code-entropy.test.ts` | backup codes do not depend on a global this package never needed |
| 3 | `providers/mfa/__tests__/mfa-backup-code-single-use.test.ts` | a backup code is spent once, as the docstring says |
| 2 | `providers/mfa/__tests__/mfa-facet-identity.test.ts` | facet registry identity |
| 1 | `providers/mfa/__tests__/mfa-provider-thunk.test.ts` | mfaProvider thunk |

## api-key

API keys — 7 files, 66 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 24 | `providers/api-key/__tests__/apikeys.test.ts` | ApiKeysFacet; create; verify (+5) |
| 13 | `providers/api-key/__tests__/api-key.test.ts` | api-key provider; tenant-boundary defense |
| 9 | `providers/api-key/__tests__/api-key-entropy-floor.test.ts` | the api-key secret must have enough bytes to be a secret; a facet built by hand runs the same check; a key verify would refuse is never minted |
| 9 | `providers/api-key/__tests__/apikeys-metadata-parser.test.ts` | ApiKeysFacet - metadata parser; list(); verify() (+1) |
| 4 | `providers/api-key/__tests__/api-key-session-lifetime.test.ts` | a session an api key signed in |
| 4 | `providers/api-key/__tests__/apikeys-date-fidelity.test.ts` | ApiKeysFacet date fidelity |
| 3 | `providers/api-key/__tests__/api-key-limiter-refusal.test.ts` | a spent bucket is a refusal, whatever shape the limiter reports it in |

## orgs

Organizations, teams, members, invites, access control — 5 files, 67 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 37 | `core/orgs/__tests__/orgs-boundary.test.ts` | membership answers only for the org that was asked about; granting roles cannot create a membership; leaving and rejoining (+4) |
| 11 | `core/orgs/__tests__/orgs-roles-sanitization.test.ts` | OrgsFacet roles sanitization; addMember; setRoles |
| 11 | `core/orgs/__tests__/orgs.test.ts` | OrgsFacet; addMember; setRoles + resolveMembership (+2) |
| 5 | `core/orgs/__tests__/orgs-toctou-add-member.test.ts` | OrgsFacet.addMember - TOCTOU defense |
| 3 | `adapters/memory/__tests__/orgs-absence-raises.test.ts` | the orgs store raises on a miss |

## admin-actor

Admin / impersonation / actor context — 4 files, 39 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 26 | `core/flows/__tests__/flows-signup-impersonate.test.ts` | FlowsImpl - signup state machine; FlowsImpl - impersonation; the tenant |
| 7 | `core/actor/__tests__/actor.test.ts` | actor context |
| 5 | `core/actor/__tests__/actor.pg.e2e.test.ts` **[env-gated]** |  |
| 1 | `core/actor/__tests__/actor.mysql.e2e.test.ts` **[env-gated]** |  |

## sessions

Sessions (lifetime, revocation, refresh, multi-session) — 18 files, 268 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 82 | `core/sessions/__tests__/sessions.test.ts` | SessionsFacet; create(); create() validates the impersonation window (+14) |
| 51 | `core/sessions/__tests__/sessions.redis.test.ts` | RedisSessionImpl; RedisSessionImpl - the identity index is bounded |
| 22 | `core/engine/__tests__/resolve-session-revocation.test.ts` | resolveSession() revocation, on both resolution paths; resolveBySid, called directly; AuthEngine.resolveSession readers |
| 20 | `__tests__/session-security.e2e.test.ts` **[env-gated]** | session fixation: the identifier changes on every privilege change; idle and absolute timeouts are two separate deadlines; revocation reaches the row, not just the cache (+3) |
| 19 | `core/sessions/__tests__/sessions.redis-parser.e2e.test.ts` **[env-gated]** | the parser never throws, and never quietly loses a factor; where the parser does hold its contract |
| 13 | `core/sessions/__tests__/sessions.redis-integrity.test.ts` | RedisSessionImpl row integrity; rotatedAt / createdAt fail closed; fields whose coercion switched a defence off (+3) |
| 10 | `core/sessions/__tests__/expiry-is-not-revocation.test.ts` | a session that timed out says so, and is still absence; a JWT past its exp is the same answer |
| 10 | `core/sessions/__tests__/sessions.pg.e2e.test.ts` **[env-gated]** | dialect behaviour the sqlite suite cannot reach; CHECK constraints that ONLY Postgres enforces; R1 lost update — does Postgres behave like Redis? (+1) |
| 9 | `core/engine/__tests__/resolve-session.pg.e2e.test.ts` **[env-gated]** |  |
| 5 | `core/engine/__tests__/sliding-session.test.ts` |  |
| 5 | `core/sessions/__tests__/expiry-cleanup-is-not-the-gate.test.ts` | an expiry cleanup that fails does not become the answer |
| 5 | `core/sessions/__tests__/session-invariants-parity.test.ts` | the in-process session stores enforce what every dialect CHECKs |
| 4 | `__tests__/revocation.multiprocess.e2e.test.ts` **[env-gated]** |  |
| 4 | `core/sessions/__tests__/freshness-window-parity.test.ts` | the freshness window is bounded at both ends; a session carrying a future rotatedAt is not fresh to read back |
| 4 | `core/sessions/__tests__/sessions.redis.e2e.test.ts` **[env-gated]** | shared Sessions.Store contract; races, against real latency; gc at scale |
| 3 | `core/sessions/__tests__/active-devices.test.ts` |  |
| 2 | `core/sessions/__tests__/sessions.valkey.e2e.test.ts` **[env-gated]** |  |
| 0 | `core/sessions/__tests__/compliance.test.ts` | RedisSessionImpl compliance matrix |

## passwords

Password hashing, rehash, rotation, pwned checks — 13 files, 135 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 33 | `core/crypto/__tests__/crypto.test.ts` | randomToken; sha256; timingSafeEqual (+1) |
| 17 | `providers/passwords/hashers/__tests__/hasher-params.test.ts` | ScryptHasher refuses parameters that write a row its own reader rejects; Argon2idHasher refuses a work factor that is not one; what each hasher publishes about its own cost (+1) |
| 16 | `providers/passwords/__tests__/passwords.facet.test.ts` | PasswordsFacet; strength validation; set + verify happy path (+3) |
| 13 | `providers/passwords/hashers/__tests__/scrypt.hasher.test.ts` | AuthScryptHasher; a stored hash carrying no key material |
| 10 | `providers/passwords/__tests__/passwords.test.ts` | password provider - end-to-end sign-in; email case-folding parity |
| 9 | `core/engine/__tests__/fips-hasher-evidence.test.ts` | the FIPS hasher is evidenced, not attested, when the engine can see it; what the hashers publish about those parameters |
| 9 | `providers/passwords/hashers/__tests__/argon2.hasher.test.ts` **[env-gated]** | AuthArgon2idHasher (contract) |
| 6 | `providers/passwords/hashers/__tests__/argon2-missing-peer.test.ts` | the default hasher with its optional peer dependency missing; with the module present it still tells a wrong password from a broken install |
| 5 | `core/flows/__tests__/flows-password-reset-proves-address.test.ts` | a password reset proves the address it was mailed to |
| 5 | `providers/passwords/__tests__/passwords-config-caps.test.ts` | the sign-in cap follows maxLength; a length it cannot enforce is refused |
| 5 | `providers/passwords/__tests__/passwords-timing-defense.test.ts` | PasswordsFacet.verify - username-enumeration timing defense |
| 4 | `providers/passwords/__tests__/passwords-auto-rehash.test.ts` | autoRehash rolls a parameter upgrade out on sign-in; a rehash racing a password change |
| 3 | `core/flows/__tests__/flows-password-reset-timing-defense.test.ts` | flows.requestPasswordReset - timing-defense |

## magic-link

Magic link, email verification, one-time tokens — 7 files, 131 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 33 | `providers/magic-link/__tests__/magic-link.test.ts` | magic-link provider; begin; callbackPath open-redirect defense (+4) |
| 24 | `__tests__/token-quality.e2e.test.ts` **[env-gated]** | session identifiers; CSRF tokens; API keys (+3) |
| 21 | `core/flows/__tests__/flows-deletion-undo-token.test.ts` | account deletion - the undo token; minting; redeeming (+1) |
| 20 | `__tests__/one-shot-credentials.e2e.test.ts` **[env-gated]** | TOTP is single-use within its validity window; backup codes are single-use; credential revocation reaches the row (+1) |
| 18 | `providers/magic-link/__tests__/magic-link.e2e.test.ts` **[env-gated]** | a link works exactly once; tokens that should never work; one identity’s link is not another’s (+2) |
| 11 | `core/flows/__tests__/flows-email-verification.test.ts` | FlowsImpl - email verification |
| 4 | `providers/magic-link/__tests__/magic-link-timing-defense.test.ts` | magic-link.begin - timing-defense |

## rate-limit

Rate limiting / brute-force / lockout — 6 files, 48 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 17 | `limiters/__tests__/limiter-bounds.test.ts` | AuthMemoryLimiter - input bounds; weight floor; key bounds (+2) |
| 9 | `limiters/redis/__tests__/redis-limiter.e2e.test.ts` **[env-gated]** |  |
| 8 | `limiters/__tests__/redis-limiter.test.ts` | RedisLimiter |
| 7 | `core/flows/__tests__/unlink-lockout-parity.test.ts` | the last-factor guard, through both doors |
| 5 | `limiters/__tests__/limiter-config-bounds.test.ts` |  |
| 2 | `limiters/valkey/__tests__/valkey-limiter.e2e.test.ts` **[env-gated]** |  |

## captcha

CAPTCHA — 3 files, 58 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 48 | `core/captcha/__tests__/captcha-verifiers.test.ts` | the http response is trusted as far as its body parses; the fields a siteverify response carries beyond success; what is sent to the provider (+3) |
| 5 | `core/captcha/__tests__/captcha.siteverify.e2e.test.ts` | E2E siteverify against a real HTTP peer |
| 5 | `core/engine/__tests__/engine.captcha.test.ts` | auth.captcha |

## adapters

Store adapters + schema/migration layer — 24 files, 210 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 31 | `adapters/drizzle/pg/__tests__/adapter.pg.e2e.test.ts` **[env-gated]** | identities; credentials; sessions (+2) |
| 26 | `adapters/drizzle/__tests__/drizzle.stored-json.test.ts` | storedDate; isProviderLink; isFactor (+4) |
| 25 | `adapters/drizzle/pg/__tests__/compliance.pg.e2e.test.ts` **[env-gated]** | optimistic locking under a real transaction; unique indexes on the profile jsonb; jsonb column round trips (+3) |
| 20 | `adapters/drizzle/mysql/__tests__/compliance.mysql.e2e.test.ts` **[env-gated]** | the re-SELECT that stands in for RETURNING; JSON_CONTAINS and json path lookups; a value a column cannot hold (+4) |
| 17 | `adapters/drizzle/sqlite/__tests__/dialect-contract.test.ts` | DrizzleSqlite store-contract divergences; unique index violations arrive typed; identities.link (+6) |
| 14 | `core/drivers/__tests__/redis-like.test.ts` | FakeRedis - sorted sets; FakeRedis - TTL applies to every key type |
| 12 | `core/engine/__tests__/transaction.pg.e2e.test.ts` **[env-gated]** |  |
| 10 | `adapters/valkey/__tests__/valkey.e2e.test.ts` **[env-gated]** | the translation the adapter exists for; the rest of the surface; a real store driven entirely through the adapter |
| 8 | `adapters/__tests__/adapter.test.ts` | AdapterStore.run; the adapters entry |
| 8 | `adapters/valkey/__tests__/valkey.test.ts` | valkeyAdapter translation; valkeySessionImpl compliance matrix; valkeyDPoPNonceStore (+1) |
| 5 | `adapters/__tests__/identifier-folding.test.ts` |  |
| 5 | `adapters/drizzle/sqlite/__tests__/sqlite.constraints.test.ts` | uq_auth_credentials_password; profile length caps |
| 5 | `adapters/memory/__tests__/patch-metadata-stress.test.ts` | memory.credentials.patchMetadata - concurrency & convergence |
| 4 | `adapters/memory/__tests__/create-with-providers-toctou.test.ts` | MemoryAdapter.create - provider-sub uniqueness |
| 4 | `adapters/memory/__tests__/find-by-email-profile-shapes.test.ts` | MemoryAdapter find({ email }) matches the address and nothing else |
| 3 | `adapters/drizzle/sqlite/__tests__/async-driver.test.ts` | DrizzleSqlite over an async driver |
| 3 | `adapters/drizzle/sqlite/__tests__/sqlite.schema.test.ts` | every declaration reaches the generated DDL; the relational query API the schema registers |
| 2 | `adapters/__tests__/declared-range.test.ts` | every adapter raises only what its map declares |
| 2 | `adapters/drizzle/__tests__/drizzle.rows.test.ts` | rowsWithLinks |
| 2 | `adapters/drizzle/mysql/__tests__/mysql.schema.test.ts` | every mysql declaration reaches the generated DDL |
| 2 | `adapters/drizzle/pg/__tests__/pg.schema.test.ts` | every pg declaration reaches the generated DDL |
| 2 | `adapters/drizzle/sqlite/__tests__/foreign-keys-ready.test.ts` | the sqlite adapter waits for foreign keys before it answers |
| 0 | `adapters/drizzle/sqlite/__tests__/compliance.test.ts` | DrizzleSqlite compliance matrix |
| 0 | `adapters/memory/__tests__/compliance.test.ts` | MemoryAdapter compliance matrix |

## engine-config

Engine, config, context, flows, identities, errors, utils — 60 files, 800 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 54 | `core/identities/__tests__/identities.test.ts` | IdentitiesFacet; create; updateProfile w/ optimistic locking (+11) |
| 41 | `__tests__/hostile-input.e2e.test.ts` **[env-gated]** | injection payloads are data, not code; prototype-pollution keys are treated as ordinary data; unicode the column may not like (+7) |
| 35 | `__tests__/flows.e2e.test.ts` **[env-gated]** | password reset: the token works once; email verification; account deletion and its grace period (+3) |
| 33 | `core/__tests__/credentials.test.ts` | isRevoked; getProfileString; isSoftDeleted (+4) |
| 32 | `core/predicates/__tests__/predicates.test.ts` | isExpiredAt; the live sentinel; ordinary values (+6) |
| 30 | `core/flows/__tests__/flows-c6-open-findings.test.ts` | F14 / F15 - impersonation neither carries nor returns assurance; F17 / F18 / F19 / F20 - provider linking; F23 / F24 / F25 / F26 - signup (+2) |
| 28 | `__tests__/hostile-values.e2e.test.ts` **[env-gated]** | OIDC redirect targets; session fields nobody validates before the insert; numbers the limiter is handed (+2) |
| 26 | `__tests__/linking-and-keys.e2e.test.ts` **[env-gated]** | linking a provider account; unlinking; API keys |
| 25 | `core/errors/__tests__/errors.test.ts` | AuthError construction; the code map; toJSON strips secrets (+3) |
| 24 | `core/config/__tests__/create-auth.test.ts` | every knob the config type accepts reaches the engine; the defaults it picks when a knob is omitted; the strict flag (+1) |
| 23 | `core/__tests__/strict.test.ts` | AuthEngine.strict(); production rejections; AuthEngine.strict() - signing secrets (+2) |
| 21 | `core/flows/__tests__/flows-extracts-direct.test.ts` | flows/password-reset.ts - direct exports; flows/email-verification.ts - direct exports; flows/account-deletion.ts - direct exports (+3) |
| 20 | `core/provider/__tests__/provider-dispatch.test.ts` | what an id may be; what list advertises against what begin accepts; resolving a facet by its class |
| 19 | `core/flows/__tests__/flows-account-deletion.test.ts` | FlowsImpl - account deletion |
| 18 | `core/__tests__/define-auth.test.ts` | createAuth |
| 18 | `core/config/__tests__/config-ergonomics.test.ts` | idempotency is built the way the limiter is, and held by the host; anomaly thresholds are reachable from the config; every config-position class has a factory beside it (+1) |
| 17 | `core/flows/__tests__/signup-squat-reclaim.test.ts` | D1 - a squat is reclaimed; D1 - an account is not a squat; D1 - a completed signup stops being reclaimable |
| 16 | `__tests__/static-analysis.test.ts` | No Math.random in security paths; No bespoke timing-unsafe compares on secrets; No CommonJS require in the source (+9) |
| 16 | `core/__tests__/compliance.test.ts` | authResolveCompliance; assertComplianceStrict; readCompliancePreset - SEC: brand validation |
| 16 | `core/flows/__tests__/flows-c6-audit-fixes.test.ts` | F1 - requestPasswordReset is not an enumeration oracle; F8 / F9 - one credential kind, four flows, one discriminator; F21 - beginSignUp is rate limited (+2) |
| 15 | `core/credentials/__tests__/credentials.test.ts` | isCredentialExpired; isRevoked; toPublicCredential |
| 14 | `core/__tests__/batch.test.ts` | batch operations |
| 14 | `core/engine/__tests__/strict-event-delivery.test.ts` | strict() over a bus that runs every handler on every server |
| 14 | `core/errors/__tests__/errors.drivers.test.ts` | sqlError |
| 12 | `core/identities/__tests__/deleted-identity-guards.test.ts` | a deleted identity cannot be authenticated; the identities facet answers with the row or rejects |
| 12 | `core/identities/__tests__/email-canonicalisation.test.ts` | canonicalEmail; emailSpellings; toEmailList (+1) |
| 11 | `core/engine/__tests__/strict-dev-only-implementations.test.ts` | strict() rejects a dev-only implementation NODE_ENV did not catch; strict() rejects magic-link wired with no deliver |
| 11 | `core/flows/__tests__/flows-signup-tampered-flow.test.ts` | flows signup - tampered flow metadata; flows signup - a stage that does not exist |
| 11 | `core/url-validators/__tests__/url-validators.test.ts` | isSafeCallbackPath; accepts ordinary same-origin paths; refuses anything that could move the authority (+6) |
| 10 | `core/__tests__/plugin.test.ts` | Plugin system; Plugin events on a fleet |
| 10 | `core/flows/__tests__/flows-callback-path-sanitization.test.ts` | FlowsImpl - callbackPath sanitization; requestPasswordReset; requestEmailVerification (+2) |
| 9 | `core/__tests__/url-validators.test.ts` | isSafeCallbackPath; accepts safe same-origin paths; rejects userinfo-injection (the bug) (+6) |
| 9 | `core/flows/__tests__/flows-linking.test.ts` | FlowsImpl - account linking |
| 8 | `core/engine/__tests__/engine.bound-providers.test.ts` | bound facade - provider-owned facets |
| 8 | `core/pending/__tests__/pending.test.ts` | createPending |
| 7 | `__tests__/engine.e2e.test.ts` **[env-gated]** |  |
| 7 | `core/__tests__/answer.test.ts` | answer |
| 7 | `core/engine/__tests__/engine-capability-getters.test.ts` | engine capability getters |
| 7 | `core/engine/__tests__/engine.bound.test.ts` | AuthEngine.withTransaction |
| 7 | `core/engine/__tests__/strict-store-sweep.test.ts` | the production store sweep covers every slot in the stores bag |
| 7 | `core/flows/__tests__/signup-flow-token-expiry.test.ts` | a signup flow token stops working when its window closes; the credential's own cap still refuses a flow claiming to be live |
| 6 | `core/credentials/__tests__/credential-expiry-gates.test.ts` | a password past its expiresAt; a passkey past its expiresAt; a backup code past its expiresAt |
| 6 | `core/url-validators/__tests__/hostname-blocklist.test.ts` | the outbound host guard refuses internal names, not only internal addresses |
| 6 | `test/__tests__/test-helpers.test.ts` | authCreateTest() |
| 5 | `__tests__/lazy-peer-deps.test.ts` | the packages the source loads |
| 5 | `core/flows/__tests__/flows-delivery.test.ts` | a flow that mails a link reads what deliver answered; a link mailed without awaiting |
| 5 | `core/flows/__tests__/flows-expired-session-gates.test.ts` | expired sessions are refused at every privileged gate |
| 5 | `core/flows/__tests__/flows-link-toctou.test.ts` | FlowsImpl.linkProvider - TOCTOU defense |
| 5 | `core/identities/__tests__/identity-invariants-parity.test.ts` | the in-process identity store enforces what every dialect CHECKs |
| 4 | `__tests__/readme-imports.test.ts` | the imports we ship to consumers |
| 4 | `core/config/__tests__/config-forwards-cfg.test.ts` | createAuth forwards the whole engine config |
| 4 | `core/flows/__tests__/flows-provider-id-cap.test.ts` | FlowsImpl provider id reflection-DoS defense |
| 4 | `core/identities/__tests__/identities.soft-deleted.test.ts` | isSoftDeleted |
| 4 | `core/provider/__tests__/provider-registry.test.ts` | Providers capability registry |
| 3 | `__tests__/public-surface.test.ts` | public surface |
| 3 | `core/flows/__tests__/flows-token-ttl.test.ts` | password reset: a refused lifetime says nothing about who exists |
| 3 | `test/__tests__/e2e-sources.test.ts` | the e2e manifest |
| 2 | `core/__tests__/patch.test.ts` | stripUndefined |
| 2 | `core/engine/__tests__/base-url.test.ts` | new AuthEngine reads baseUrl as createAuth does |
| 2 | `core/engine/__tests__/provider-registry.test.ts` | provider registry |

