# Test map: better-auth v1.7.2

Generated 2026-10-21 by `benchmark/scripts/map.ts`. Do not hand-edit.

**377 test files, 6045 statically counted cases.** Static counting is a lower bound — see `benchmark/README.md`.

| Cluster | Files | Tests |
| --- | --- | --- |
| [SCIM provisioning](#scim) | 33 | 265 |
| [Billing / Stripe](#billing) | 10 | 168 |
| [CLI, codegen, release tooling](#cli) | 30 | 349 |
| [MCP server auth](#mcp) | 6 | 63 |
| [CIMD (client identity metadata documents)](#cimd) | 9 | 149 |
| [i18n / localised messages](#i18n) | 1 | 18 |
| [Telemetry + instrumentation](#telemetry) | 6 | 43 |
| [OpenAPI spec generation](#openapi) | 2 | 32 |
| [Runtime + bundler smoke (bun/deno/CF/esbuild/vite/tsconfig)](#runtime-smoke) | 16 | 26 |
| [Email OTP / phone (SMS) OTP sign-in](#email-otp) | 2 | 126 |
| [Device authorization grant (RFC 8628)](#device-auth) | 4 | 118 |
| [Username provider, anonymous auth, last-login-method](#username-anon) | 6 | 115 |
| [Client SDK (vanilla + react/vue/solid/svelte + expo/electron)](#client) | 15 | 248 |
| [Framework integration, browser-driven (Playwright)](#frameworks-client) | 7 | 16 |
| [SAML + SSO provider registry](#saml-sso) | 18 | 584 |
| [OIDC provider (authorize/token/DCR/introspect/resources)](#oidc-op) | 40 | 791 |
| [Transport: cookies, bearer, JWT, DPoP, CSRF, origin](#transport) | 10 | 274 |
| [OAuth2 client + social providers](#oauth-social) | 31 | 539 |
| [Passkey / WebAuthn](#passkey) | 2 | 41 |
| [MFA: TOTP, backup codes, step-up](#mfa) | 4 | 82 |
| [API keys](#api-key) | 2 | 193 |
| [Organizations, teams, members, invites, access control](#orgs) | 8 | 265 |
| [Admin / impersonation / actor context](#admin-actor) | 2 | 96 |
| [Sessions (lifetime, revocation, refresh, multi-session)](#sessions) | 6 | 120 |
| [Password hashing, rehash, rotation, pwned checks](#passwords) | 4 | 76 |
| [Magic link, email verification, one-time tokens](#magic-link) | 3 | 62 |
| [Rate limiting / brute-force / lockout](#rate-limit) | 1 | 29 |
| [CAPTCHA](#captcha) | 1 | 33 |
| [Store adapters + schema/migration layer](#adapters) | 60 | 408 |
| [Engine, config, context, flows, identities, errors, utils](#engine-config) | 38 | 716 |

## scim

SCIM provisioning — 33 files, 265 tests, scope `ba-only-gap`.

| Tests | File | Suites |
| --- | --- | --- |
| 22 | `packages/scim/src/scim-active-normalization.test.ts` | SCIM User active ingress helper; SCIM User multi-valued primary ingress helper; SCIM User active HTTP normalization (+1) |
| 18 | `packages/scim/src/scim-http-contract.test.ts` | SCIM HTTP contract |
| 18 | `packages/scim/src/scim-identity-resolution.test.ts` | SCIM explicit identity resolution; SCIM active User links |
| 17 | `packages/scim/src/collection-query.test.ts` | parseSCIMCollectionQuery; collection pagination; collection filters (+1) |
| 17 | `packages/scim/src/scim-user-patch.test.ts` | SCIM User PATCH provider compatibility; SCIM User compatibility with pre-serializedAttributes rows |
| 15 | `packages/scim/src/scim-dynamic-authentication.test.ts` | SCIM dynamic connection authentication |
| 14 | `packages/scim/src/scim-enterprise-user.test.ts` | SCIM classic Enterprise User provisioning |
| 14 | `packages/scim/src/scim-managed-connections.test.ts` | SCIM managed connections |
| 14 | `packages/scim/src/scim-okta-conformance.test.ts` | Okta SCIM 2.0 SPEC test; Okta SCIM 2.0 CRUD test net wire sequence |
| 13 | `packages/scim/src/scim-groups-v2.test.ts` | SCIM connection-owned Groups |
| 12 | `packages/scim/src/scim-projection.test.ts` | SCIM role projection |
| 10 | `packages/scim/src/scim-connections.test.ts` | SCIM connection provisioning |
| 9 | `packages/scim/src/resource-attribute-projection.test.ts` | projectSCIMResourceAttributes |
| 8 | `packages/scim/src/schema-conformance.test.ts` | SCIM core schema conformance |
| 8 | `packages/scim/src/scim-user-concurrency.test.ts` | SCIM User concurrency |
| 7 | `packages/scim/src/scim-entra-conformance.test.ts` | SCIM User PATCH against Microsoft Entra ID attribute mappings |
| 6 | `packages/scim/src/scim-attribute-projection.test.ts` | SCIM core-schema-qualified attribute projection |
| 5 | `packages/scim/src/scim-google-conformance.test.ts` | Google Workspace/Cloud Identity automated provisioning client; R1 — bearer/access token auth, admin-pasted, no OAuth flow; R3 — deprovisioning: suspend and hard-delete are independent paths (+1) |
| 5 | `packages/scim/src/scim-group-cardinality.test.ts` | SCIM Group direct-member cardinality |
| 5 | `packages/scim/src/scim-group-patch-delta.test.ts` | SCIM incremental Group PATCH |
| 4 | `packages/scim/src/scim-filter-interoperability.test.ts` | SCIM provider filter interoperability |
| 3 | `packages/scim/src/discovery.test.ts` | SCIM discovery |
| 3 | `packages/scim/src/resource-key.test.ts` | SCIM persisted keys |
| 3 | `packages/scim/src/scim-create-uniqueness.test.ts` | SCIM resource create uniqueness races |
| 3 | `packages/scim/src/scim-sqlite.test.ts` | SCIM SQLite integration |
| 2 | `e2e/integration/nextjs-demo/e2e/scim-demo.spec.ts` |  |
| 2 | `packages/scim/src/scim-group-list-query.test.ts` | SCIM Group collection queries |
| 2 | `packages/scim/src/scim-http-e2e.test.ts` | SCIM HTTP end-to-end |
| 2 | `packages/scim/src/scim-provisioning-domain.test.ts` | SCIM provisioning domain immutability |
| 1 | `packages/scim/src/scim-profile.test.ts` | SCIM canonical User profiles |
| 1 | `packages/scim/src/scim-sso-http-e2e.test.ts` | SCIM-provisioned SSO authentication over HTTP |
| 1 | `packages/scim/src/scim-sso-registration.test.ts` | SCIM and SSO registration coexistence |
| 1 | `packages/scim/src/scim-user-fencing.test.ts` | SCIM User connection fencing |

## billing

Billing / Stripe — 10 files, 168 tests, scope `ba-only-by-design`.

> Out of scope: duck-auth is not a billing library.

| Tests | File | Suites |
| --- | --- | --- |
| 36 | `packages/stripe/test/subscription.test.ts` | stripe subscription; trial abuse prevention; restore subscription (+2) |
| 27 | `packages/stripe/test/webhook.test.ts` | stripe webhook; Webhook Error Handling (Stripe v19); webhook: cancel_at_period_end cancellation (+1) |
| 23 | `packages/stripe/test/checkout.test.ts` | stripe checkout; line item replacement on plan change; line item add/remove on asymmetric plan change (+4) |
| 20 | `packages/stripe/test/stripe-organization.test.ts` | stripe - organization customer; stripe - organizationHooks integration |
| 16 | `packages/stripe/test/customer.test.ts` | stripe customer; getCustomerCreateParams; Duplicate customer prevention on signup (+3) |
| 14 | `packages/stripe/test/seat-based-billing.test.ts` | seat-based billing; checkout with auto-managed seats; checkout with additional line items (+5) |
| 10 | `packages/stripe/test/middleware.test.ts` | referenceMiddleware; referenceMiddleware - user subscription; referenceMiddleware - organization subscription |
| 10 | `packages/stripe/test/utils.test.ts` | escapeStripeSearchValue; resolvePlanItem |
| 8 | `packages/stripe/test/metadata.test.ts` | stripe metadata prototype pollution guard; stripe metadata helpers |
| 4 | `packages/stripe/test/plugin.test.ts` | stripe type |

## cli

CLI, codegen, release tooling — 30 files, 349 tests, scope `ba-only-gap`.

| Tests | File | Suites |
| --- | --- | --- |
| 79 | `packages/cli/test/generate.test.ts` | generate; command output paths; JSON field support in CLI generators (+6) |
| 66 | `packages/cli/src/commands/init/utility/plugin.test.ts` | Init CLI - plugin utility; empty or undefined plugins; plugins without arguments (+24) |
| 32 | `packages/release-tooling/test/release-workflows.test.ts` | release notes command security; release publication security; release tooling package boundary |
| 29 | `packages/cli/test/get-config.test.ts` | getConfig; tsconfig paths resolution (user-reported scenarios); SvelteKit virtual modules and Vite asset imports (user-reported scenarios) |
| 16 | `packages/release-tooling/test/release-collection.test.ts` | release version validation; release manifest validation; release changeset readiness (+1) |
| 13 | `packages/release-tooling/test/release-notes-comment.test.ts` | wrapReleaseNotesComment; extractReleaseNotesComment |
| 12 | `packages/cli/test/generate-all-db.test.ts` | generate drizzle schema for all databases; generate drizzle schema for all databases with passkey plugin |
| 11 | `packages/cli/src/commands/init/utility/database.test.ts` | init CLI - database generation; prisma; drizzle (+2) |
| 11 | `packages/release-tooling/test/release-render.test.ts` | AI release-note rewrites |
| 10 | `packages/cli/src/commands/init/utility/imports.test.ts` | Init CLI - imports utility |
| 8 | `packages/cli/test/info.test.ts` | info command |
| 8 | `packages/release-tooling/test/changeset-rewrite.test.ts` | changeset rewriting |
| 7 | `packages/cli/test/create-admin.test.ts` | create-admin |
| 6 | `packages/cli/src/commands/init/utility/env.test.ts` | Init CLI - env utility functions; getEnvFiles; parseEnvFiles (+3) |
| 6 | `packages/release-tooling/test/change-classifier.test.ts` | change classification |
| 5 | `packages/release-tooling/test/generated-copy.test.ts` | generated Markdown policy |
| 5 | `packages/release-tooling/test/github.test.ts` | GitHubReader |
| 5 | `packages/release-tooling/test/release-rewrite.test.ts` | release-note rewriting |
| 4 | `packages/cli/src/commands/init/utility/auth-config.test.ts` | Init CLI - auth config generation |
| 4 | `packages/cli/test/upgrade.test.ts` | upgradeAction |
| 3 | `packages/cli/test/migrate.test.ts` | migrate base auth instance; migrate auth instance with plugins; migrate an index-only schema change |
| 2 | `packages/cli/test/migrate-cli.test.ts` | auth migrate: refusing a destructive column add; auth generate: emitting the refused migration with a warning |
| 2 | `packages/release-tooling/test/conventional-header.test.ts` | parseConventionalHeader |
| 2 | `packages/release-tooling/test/generate-structured.test.ts` | generateStructured |
| 1 | `packages/cli/src/commands/init/utility/framework.test.ts` | Init CLI - framework utility; autoDetectFramework; route handler paths (+1) |
| 1 | `packages/release-tooling/test/actions-output.test.ts` | Actions output |
| 1 | `packages/release-tooling/test/changeset-recommend.test.ts` | changeset recommendation |
| 0 | `packages/cli/test/check-package-managers.test.ts` | detectPackageManager |
| 0 | `packages/cli/test/init.test.ts` | initAction |
| 0 | `packages/cli/test/install-dependencies.test.ts` | installDependencies |

## mcp

MCP server auth — 6 files, 63 tests, scope `ba-only-gap`.

| Tests | File | Suites |
| --- | --- | --- |
| 20 | `packages/mcp/src/plugin.test.ts` | mcp plugin; dynamic client registration; discovery metadata (+4) |
| 16 | `packages/mcp/src/require-mcp-auth.test.ts` | requireMcpAuth |
| 10 | `packages/mcp/src/handler.test.ts` | createMcpProtectedRequestHandler |
| 9 | `packages/mcp/src/mcp.test.ts` | official SDK AuthInfo mapping; mcp; MCP SDK v2 explicit DCR flow |
| 6 | `packages/cimd/src/mcp-e2e.test.ts` | official SDK AuthInfo mapping; CIMD-first MCP authorization with the official SDK v2 |
| 2 | `packages/mcp/src/public-types.test.ts` | public MCP surface |

## cimd

CIMD (client identity metadata documents) — 9 files, 149 tests, scope `ba-only-gap`.

| Tests | File | Suites |
| --- | --- | --- |
| 89 | `packages/cimd/src/validate-metadata-document.test.ts` | isCimdClientIdUrlCandidate; validateClientIdUrl; validateCimdMetadata |
| 16 | `packages/cimd/src/cache.test.ts` | CIMD HTTP metadata cache |
| 11 | `packages/cimd/src/fetch-governor.test.ts` | CIMD metadata fetch governor |
| 10 | `packages/cimd/src/cimd.test.ts` | Client ID Metadata Document - integration |
| 8 | `packages/cimd/src/flows.test.ts` | CIMD - token exchange flow; CIMD - refresh preserves admin-set flags; CIMD - metadata document URL policy |
| 7 | `packages/cimd/src/node.test.ts` | Node CIMD metadata transport |
| 4 | `packages/cimd/src/client-store.test.ts` | fetchClientMetadataDocument |
| 2 | `e2e/smoke/test/cimd.spec.ts` | CIMD end-to-end flow |
| 2 | `packages/cimd/src/public-types.test.ts` | public CIMD surface |

## i18n

i18n / localised messages — 1 files, 18 tests, scope `ba-only-gap`.

| Tests | File | Suites |
| --- | --- | --- |
| 18 | `packages/i18n/src/i18n.test.ts` | i18n plugin; locale detection from Accept-Language header; locale detection from cookie (+5) |

## telemetry

Telemetry + instrumentation — 6 files, 43 tests, scope `ba-only-gap`.

| Tests | File | Suites |
| --- | --- | --- |
| 11 | `packages/core/src/instrumentation/instrumentation.test.ts` | instrumentation |
| 8 | `packages/better-auth/src/instrumentation.endpoint.test.ts` | endpoints instrumentation |
| 7 | `packages/better-auth/src/instrumentation.db.test.ts` | database instrumentation |
| 7 | `packages/core/src/instrumentation/pure.test.ts` | instrumentation (pure entry) |
| 6 | `packages/telemetry/src/telemetry.test.ts` | telemetry |
| 4 | `packages/core/src/instrumentation/noop.test.ts` | instrumentation noop |

## openapi

OpenAPI spec generation — 2 files, 32 tests, scope `ba-only-by-design`.

> Removed with the route layer in PR #288.

| Tests | File | Suites |
| --- | --- | --- |
| 30 | `packages/better-auth/src/plugins/open-api/open-api.test.ts` | open-api |
| 2 | `packages/passkey/src/open-api.test.ts` | passkey open-api |

## runtime-smoke

Runtime + bundler smoke (bun/deno/CF/esbuild/vite/tsconfig) — 16 files, 26 tests, scope `ba-only-gap`.

| Tests | File | Suites |
| --- | --- | --- |
| 5 | `e2e/smoke/test/fixtures/cloudflare/test/auth-flow.test.ts` | email and password authentication |
| 3 | `e2e/smoke/test/esbuild.spec.ts` |  |
| 3 | `e2e/smoke/test/ipv6.spec.ts` | IPv6 rate limiting |
| 3 | `e2e/smoke/test/saml.spec.ts` | SAML SSO |
| 1 | `e2e/smoke/test/bun-default-export.spec.ts` | (bun) zero-config default export |
| 1 | `e2e/smoke/test/bun.spec.ts` | (bun) simple server |
| 1 | `e2e/smoke/test/cloudflare.spec.ts` | (cloudflare) simple server |
| 1 | `e2e/smoke/test/deno-default-export.spec.ts` | (deno) zero-config default export |
| 1 | `e2e/smoke/test/deno.spec.ts` | (deno) simple server |
| 1 | `e2e/smoke/test/fixtures/cloudflare/test/cold-start.test.ts` |  |
| 1 | `e2e/smoke/test/fixtures/cloudflare/test/migration.test.ts` |  |
| 1 | `e2e/smoke/test/passkey-preauth.spec.ts` | (node) passkey pre-auth |
| 1 | `e2e/smoke/test/redis.spec.ts` |  |
| 1 | `e2e/smoke/test/session-token-refresh.spec.ts` | session_token cookie refresh in stateless mode |
| 1 | `e2e/smoke/test/typecheck.spec.ts` |  |
| 1 | `e2e/smoke/test/vite.spec.ts` | (vite) client build |

## email-otp

Email OTP / phone (SMS) OTP sign-in — 2 files, 126 tests, scope `ba-only-gap`.

| Tests | File | Suites |
| --- | --- | --- |
| 86 | `packages/better-auth/src/plugins/email-otp/email-otp.test.ts` | email-otp; change email; request (+16) |
| 40 | `packages/better-auth/src/plugins/phone-number/phone-number.test.ts` | phone-number; consume phone-number OTP; phone-number callbackOnVerification on updatePhoneNumber (+15) |

## device-auth

Device authorization grant (RFC 8628) — 4 files, 118 tests, scope `ba-only-gap`.

| Tests | File | Suites |
| --- | --- | --- |
| 63 | `packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts` | device authorization plugin input validation; user code verification rate limiting; client validation (+12) |
| 47 | `packages/oauth-provider/src/device-code.test.ts` | oauth-provider device-code composition; oauth-provider device-code grant; oauth-provider device-code immutable routing (+2) |
| 7 | `packages/better-auth/src/plugins/device-authorization/schema.test.ts` | device authorization schema |
| 1 | `e2e/integration/vanilla-node/e2e/device-code.spec.ts` |  |

## username-anon

Username provider, anonymous auth, last-login-method — 6 files, 115 tests, scope `ba-only-gap`.

| Tests | File | Suites |
| --- | --- | --- |
| 48 | `packages/better-auth/src/plugins/username/username.test.ts` | username; username custom normalization; username with displayUsername validation (+7) |
| 35 | `packages/better-auth/src/plugins/last-login-method/last-login-method.test.ts` | lastLoginMethod; beforeStoreCookie hook |
| 18 | `packages/better-auth/src/plugins/anonymous/anon.test.ts` | anonymous; anonymous cleanup safeguards; anonymous linking through generic oauth (Expo) |
| 6 | `packages/better-auth/src/plugins/last-login-method/custom-prefix.test.ts` | lastLoginMethod custom cookie prefix |
| 5 | `packages/better-auth/src/plugins/admin/admin-username.test.ts` | admin + username plugin interaction |
| 3 | `packages/expo/test/last-login-method.test.ts` | last-login-method expo |

## client

Client SDK (vanilla + react/vue/solid/svelte + expo/electron) — 15 files, 248 tests, scope `ba-only-by-design`.

> duck-auth removed every client binding in PR #288; apps bring their own fetch.

| Tests | File | Suites |
| --- | --- | --- |
| 79 | `packages/electron/test/electron.test.ts` | Electron; transferUser; pkce (+6) |
| 52 | `packages/expo/test/expo.test.ts` | expo; origin override regression; expo with cookieCache (+9) |
| 39 | `packages/better-auth/src/client/client.test.ts` | run time proxy; type; useSession().data with nullable types (+1) |
| 20 | `packages/better-auth/src/client/query.test.ts` | useAuthQuery - error handling |
| 17 | `packages/better-auth/src/client/equality.test.ts` | isJsonEqual; withEquality |
| 13 | `packages/better-auth/src/client/session-refresh.test.ts` | session-refresh |
| 5 | `packages/better-auth/src/client/parser.test.ts` | parseJSON |
| 5 | `packages/better-auth/src/plugins/oauth-popup/oauth-popup.client.test.ts` | signIn.popup completion gate; popup bearer fetch plugin |
| 5 | `packages/passkey/src/client.test.ts` | passkey client |
| 4 | `packages/better-auth/src/client/url.test.ts` | url |
| 3 | `packages/better-auth/src/client/proxy.test.ts` | createDynamicPathProxy |
| 2 | `packages/better-auth/src/plugins/organization/client.test.ts` | organization |
| 2 | `packages/better-auth/src/plugins/organization/organization-client-declaration.test.ts` | organizationClient declaration emit with additionalFields |
| 1 | `packages/better-auth/src/client/client-declaration.test.ts` | client declaration emit |
| 1 | `packages/better-auth/src/client/client-ssr.test.ts` |  |

## frameworks-client

Framework integration, browser-driven (Playwright) — 7 files, 16 tests, scope `ba-only-by-design`.

> duck-auth ships no routes or handlers, so there is no mounted app to drive.

| Tests | File | Suites |
| --- | --- | --- |
| 8 | `packages/better-auth/src/integrations/next-js.test.ts` | next-js integration; next/headers module loading |
| 3 | `e2e/integration/vanilla-node/e2e/dynamic-base-url.spec.ts` |  |
| 1 | `e2e/integration/solid-vinxi/e2e/test.spec.ts` |  |
| 1 | `e2e/integration/vanilla-node/e2e/cookie-cache-signout.spec.ts` |  |
| 1 | `e2e/integration/vanilla-node/e2e/domain.spec.ts` |  |
| 1 | `e2e/integration/vanilla-node/e2e/postgres-js.spec.ts` |  |
| 1 | `e2e/integration/vanilla-node/e2e/test.spec.ts` |  |

## saml-sso

SAML + SSO provider registry — 18 files, 584 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 154 | `packages/sso/src/saml.test.ts` | private key normalization; SAML SSO with defaultSSO array; SAML SSO with signed AuthnRequests (+41) |
| 93 | `packages/sso/src/providers.test.ts` | SAML redirect URL schema; SSO provider read endpoints; GET /sso/providers (+7) |
| 88 | `packages/sso/src/oidc/discovery.test.ts` | OIDC Discovery; computeDiscoveryUrl; validateDiscoveryUrl (+13) |
| 47 | `packages/sso/src/oidc.test.ts` | SSO; SSO disable implicit sign in; provisioning (+10) |
| 38 | `packages/sso/src/saml/algorithms.test.ts` | validateSAMLAlgorithms; signature validation; encryption validation (+5) |
| 28 | `packages/sso/src/utils.test.ts` | parseProviderEmailVerified; parseProviderDomains; validateEmailDomain (+4) |
| 25 | `packages/sso/src/domain-verification.test.ts` | Domain verification; POST /sso/request-domain-verification; POST /sso/verify-domain (+1) |
| 24 | `packages/sso/src/saml/assertions.test.ts` | validateSingleAssertion; valid responses (exactly 1 assertion); base64 whitespace handling (+7) |
| 19 | `packages/sso/src/linking/org-assignment.test.ts` | assignOrganizationByDomain; assignOrganizationFromProvider |
| 17 | `packages/sso/src/saml/response-binding.test.ts` | validateSAMLResponseBinding; getSAMLPostAssertionConsumerServiceUrls; parseSAMLServiceProviderMetadata (+1) |
| 15 | `packages/sso/src/routes/helpers.test.ts` | createSAMLPostForm; deriveSAMLIdentityProviderEntityID; createSP assertion-signing metadata |
| 12 | `packages/sso/src/oidc-user-resolution-http-e2e.test.ts` | SSO OIDC user resolution HTTP |
| 6 | `packages/sso/src/domain-verification-concurrency.test.ts` | domain verification concurrency |
| 5 | `packages/sso/src/linking/org-assignment.security.test.ts` | SSO verified-domain organization assignment |
| 5 | `packages/sso/src/user-resolution.test.ts` | SSO user resolution |
| 4 | `packages/sso/src/provider-reference.test.ts` | SSO provider references |
| 2 | `packages/sso/src/oidc/id-token.test.ts` | OIDC authorized party validation |
| 2 | `packages/sso/src/provider-lock.test.ts` | SSO provider account-link locking |

## oidc-op

OIDC provider (authorize/token/DCR/introspect/resources) — 40 files, 791 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 95 | `packages/oauth-provider/src/token.test.ts` | oauth token - authorization_code; redirect_uri conditional (RFC 6749 §4.1.3); oauth token - refresh_token (+14) |
| 68 | `packages/oauth-provider/src/register.test.ts` | oauth register; client metadata document grant intersection; oauth register - disableJwtPlugin (+6) |
| 46 | `packages/oauth-provider/src/authorize.test.ts` | validateIssuerUrl (RFC 9207); formatErrorURL; oauth signed query signatures (+7) |
| 46 | `packages/oauth-provider/src/oauth.test.ts` | oauth - init; oauth; oauth - prompt (+2) |
| 33 | `packages/oauth-provider/src/private-key-jwt.test.ts` | private_key_jwt authentication; isPrivateHostname; private_key_jwt registration validation |
| 31 | `packages/oauth-provider/src/extensions.test.ts` | oauth-provider extensions |
| 30 | `packages/oauth-provider/src/logout.test.ts` | oauth logout; oauth logout confirmation with a custom base path; oauth logout - disableJwtPlugin |
| 28 | `packages/oauth-provider/src/resources-e2e.test.ts` | introspection accepts entity-issued JWTs and rejects deleted-resource tokens; code grant binds authorize-time `resource`; refresh tokens preserve original resource (+6) |
| 27 | `packages/oauth-provider/src/validation-flow.test.ts` | resolveResourcePolicy — resource omission; resolveResourcePolicy — entity path; resolveResourcePolicy — enforcePerClientResources |
| 26 | `packages/oauth-provider/src/metadata.test.ts` | oauth metadata; dynamic baseURL metadata wrappers; oauth resource metadata |
| 26 | `packages/oauth-provider/src/oauthResource/endpoints.test.ts` | resource admin CRUD; resourcePrivileges gate; client/resource linking (+2) |
| 26 | `packages/oauth-provider/src/resource-discovery.test.ts` | DCR — resources field (RFC 7591 §2 extension); managed client registration resources; trusted client cache provenance (+2) |
| 23 | `packages/oauth-provider/src/oauthClient/endpoints-privileges.test.ts` | oauthClient; oauthClient dynamic registration privileges |
| 22 | `packages/oauth-provider/src/introspect.test.ts` | oauth introspect; oauth introspect - config; oauth introspect - rejects non-OAuth same-issuer JWTs |
| 22 | `packages/oauth-provider/src/oauthClient/endpoints.test.ts` | oauthClient; oauthClient private_key_jwt clients |
| 22 | `packages/oauth-provider/src/types/zod.test.ts` | SafeUrlSchema; HTTPS enforcement; dangerous schemes (+3) |
| 21 | `packages/oauth-provider/src/oauth-endpoint.integration.test.ts` | RFC envelope compliance across OAuth endpoints; oauth2Token (JSON delivery); oauth2Revoke (JSON delivery) (+4) |
| 18 | `packages/oauth-provider/src/pairwise.test.ts` | pairwise subject identifiers; pairwise DCR validation; pairwise configuration validation (+1) |
| 18 | `packages/oauth-provider/src/userinfo.test.ts` | oauth userinfo |
| 17 | `packages/oauth-provider/src/utils/query-serialization.test.ts` | searchParamsToQuery; removePromptFromQuery; removeMaxAgeFromQuery (+2) |
| 16 | `packages/oauth-provider/src/pkce-optional.test.ts` | PKCE optional - default behavior; PKCE optional - per-client opt-out; PKCE optional - dynamic client registration policy (+3) |
| 15 | `packages/core/src/oauth2/private-key-jwt-authentication.test.ts` | private_key_jwt OAuth2 helpers |
| 13 | `packages/oauth-provider/src/resources.test.ts` | collectResourceInputs; seedResources (integration via plugin init); getResource + cache |
| 12 | `packages/oauth-provider/src/backchannel-logout.test.ts` | oauth back-channel logout; oauth back-channel logout (jwt plugin disabled); oauth back-channel logout - secondaryStorage + preserveSessionInDatabase |
| 12 | `packages/oauth-provider/src/claim-authority.integration.test.ts` | opaque introspection — reserved claim stripping; opaque introspection — per-resource customClaims parity; introspection authorization (#8267) (+4) |
| 12 | `packages/oauth-provider/src/resource-challenge.test.ts` | resource server challenge |
| 11 | `packages/oauth-provider/src/oauth-endpoint.test.ts` | mapIssuesToOAuthError; zod v4 issue shape contract |
| 11 | `packages/oauth-provider/src/revoke.test.ts` | oauth revoke; oauth revoke - config |
| 7 | `packages/oauth-provider/src/oauthConsent/endpoints.test.ts` | oauthConsent |
| 6 | `packages/oauth-provider/src/claims.test.ts` | resolveAccessTokenClaims |
| 6 | `packages/oauth-provider/src/utils/timestamps.test.ts` | normalizeTimestampValue; resolveSessionAuthTime |
| 5 | `packages/oauth-provider/src/resource-binding.test.ts` | oauth-provider resource indicator binding |
| 5 | `packages/oauth-provider/src/schema.test.ts` | oauth provider schema |
| 4 | `packages/oauth-provider/src/no-store.test.ts` | oauth credential responses carry no-store |
| 3 | `packages/oauth-provider/src/client-jwks.test.ts` | validatePublicClientJwks |
| 3 | `packages/oauth-provider/src/signed-query.test.ts` | signed OAuth query |
| 2 | `packages/oauth-provider/src/private-key-jwt-e2e.test.ts` | private_key_jwt e2e |
| 1 | `packages/oauth-provider/src/client-resource.test.ts` |  |
| 1 | `packages/oauth-provider/src/oidc-rs256-profile.test.ts` | OpenID Connect RS256 provider profile |
| 1 | `packages/oauth-provider/src/public-types.test.ts` | public oauth-provider types |

## transport

Transport: cookies, bearer, JWT, DPoP, CSRF, origin — 10 files, 274 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 96 | `packages/better-auth/src/cookies/cookies.test.ts` | cookies; production environment; crossSubdomainCookies (+15) |
| 38 | `packages/better-auth/src/api/middlewares/origin-check.test.ts` | Origin Check; Fetch Metadata CSRF Protection; origin check middleware (+4) |
| 37 | `packages/better-auth/src/auth/trusted-origins.test.ts` | trusted origins; trusted origins list support; relative paths support (+4) |
| 37 | `packages/better-auth/src/plugins/jwt/jwt.test.ts` | jwt; jwt - remote signing; jwt - remote url (+9) |
| 22 | `packages/better-auth/src/plugins/jwt/multi-alg.test.ts` | custom jwt.sign callback receives signing overrides; getLatestKeyByAlg legacy-row fallback; expired-key filtering inside adapter lookups (+5) |
| 17 | `packages/core/src/oauth2/dpop.test.ts` | verifyDpopProof; enforceDpopBinding; createDpopReplayStore (+1) |
| 11 | `packages/better-auth/src/plugins/jwt/sign-overrides.test.ts` | signJWT — signing key overrides; JWKS adapter helpers |
| 7 | `packages/better-auth/src/api/routes/cookie-cache-fallback.test.ts` | cookieCache HMAC verification failure fallback |
| 7 | `packages/better-auth/src/plugins/bearer/bearer.test.ts` | bearer |
| 2 | `packages/better-auth/src/plugins/jwt/rotation.test.ts` | jwt rotation |

## oauth-social

OAuth2 client + social providers — 31 files, 539 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 115 | `packages/better-auth/src/plugins/generic-oauth/generic-oauth.test.ts` | oauth2; Okta Provider Helper; Auth0 Provider Helper (+11) |
| 74 | `packages/better-auth/src/social.test.ts` | Social Providers; Redirect URI; Disable implicit signup (+15) |
| 37 | `packages/better-auth/src/oauth2/link-account.test.ts` | oauth2 - email verification on link; oauth2 - account linking with case insensitive email; oauth2 - account linking without trustedProviders (+15) |
| 34 | `packages/better-auth/src/plugins/siwe/siwe.test.ts` | siwe; message binding |
| 34 | `packages/core/src/oauth2/verify.test.ts` | verifyBearerToken; remote introspection audience validation |
| 30 | `packages/better-auth/src/plugins/oauth-proxy/oauth-proxy.test.ts` | oauth-proxy; stateless mode (cookie-based); passthrough mode (+4) |
| 26 | `packages/core/src/social-providers/social-providers.test.ts` | OAuth account identity contract; microsoft provider; discord provider (+6) |
| 23 | `packages/better-auth/src/plugins/one-tap/one-tap.test.ts` | one-tap implicit linking gate; one-tap callbackURL origin validation; one-tap audience enforcement (+3) |
| 14 | `packages/core/src/oauth2/client-assertion.test.ts` | signPrivateKeyJwtClientAssertion |
| 14 | `packages/core/src/social-providers/google.test.ts` | google hosted domain (hd) enforcement; idToken.verifyClaims; getUserInfo (+1) |
| 13 | `packages/better-auth/src/oauth2/utils.test.ts` | decryptOAuthToken; migration scenario - issue #6018; setTokenUtil |
| 13 | `packages/core/src/oauth2/basic-credentials.test.ts` | encode/decodeBasicCredentials |
| 13 | `packages/core/src/oauth2/validate-token.test.ts` | validateToken |
| 13 | `packages/core/src/oauth2/verify-id-token.test.ts` | verifyProviderIdToken; provider regressions |
| 13 | `packages/core/src/social-providers/microsoft-entra-id.test.ts` | microsoft id_token tenant enforcement; microsoft account subject |
| 10 | `packages/better-auth/src/plugins/oauth-popup/oauth-popup.test.ts` | oauth popup completion script; oauth popup server flow |
| 9 | `packages/better-auth/src/oauth2/account-key.test.ts` | resolveOAuthAccountKey |
| 8 | `packages/core/src/oauth2/refresh-access-token.test.ts` | refreshAccessToken; parseScopeField; mergeScopes |
| 6 | `packages/better-auth/src/oauth2/state.test.ts` | parseState error mapping |
| 6 | `packages/core/src/social-providers/apple.test.ts` | apple.createAuthorizationURL; apple id_token verification |
| 5 | `packages/core/src/oauth2/reject-redirects.server.test.ts` | server-side OAuth fetches never follow a redirect to an internal host |
| 4 | `packages/core/src/oauth2/create-authorization-url.test.ts` | createAuthorizationURL |
| 4 | `packages/core/src/social-providers/facebook.test.ts` | facebook.getUserInfo (opaque access token) |
| 4 | `packages/core/src/social-providers/paypal.test.ts` | paypal.getUserInfo |
| 4 | `packages/core/src/social-providers/wechat.test.ts` | wechat.getUserInfo (no provider email) |
| 3 | `packages/core/src/oauth2/reject-redirects.runtime.test.ts` | server-side OAuth fetch refuses redirects via real betterFetch |
| 3 | `packages/core/src/oauth2/reject-redirects.test.ts` | assertResponseNotRedirect |
| 3 | `packages/core/src/social-providers/reddit.test.ts` | reddit.getUserInfo (no provider email) |
| 2 | `packages/core/src/social-providers/twitter.test.ts` | twitter.getUserInfo |
| 1 | `packages/core/src/social-providers/roblox.test.ts` | roblox.getUserInfo |
| 1 | `packages/core/src/social-providers/tiktok.test.ts` | tiktok.getUserInfo |

## passkey

Passkey / WebAuthn — 2 files, 41 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 34 | `packages/passkey/src/passkey.test.ts` | passkey; passkey ceremony and identity gating; passkey registration naming (default options) (+2) |
| 7 | `packages/passkey/src/authenticator-metadata.test.ts` | getAuthenticatorName |

## mfa

MFA: TOTP, backup codes, step-up — 4 files, 82 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 59 | `packages/better-auth/src/plugins/two-factor/two-factor.test.ts` | two factor; OTP-only enablement; two factor auth API (+20) |
| 11 | `packages/better-auth/src/plugins/two-factor/two-factor.security.test.ts` | two-factor security: sign-in does not leak session cookies (cookieCache enabled); two-factor security: sign-in does not leak session cookies (cookieCache disabled); two-factor security: chunked session_data is fully scrubbed on 2FA-required sign-in (+2) |
| 8 | `packages/better-auth/src/plugins/two-factor/two-factor.account-lockout.test.ts` | two-factor: account-level lockout across challenges |
| 4 | `packages/better-auth/src/plugins/two-factor/two-factor.attempt-cap.test.ts` | two-factor security: TOTP enforces a per-challenge attempt cap; two-factor security: backup codes enforce a per-challenge attempt cap |

## api-key

API keys — 2 files, 193 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 183 | `packages/api-key/src/api-key.test.ts` | api-key; list API keys pagination; enableSessionForAPIKeys (+16) |
| 10 | `packages/api-key/src/org-api-key.test.ts` | organization API keys; basic organization ownership; custom apiKey permissions in roles (+1) |

## orgs

Organizations, teams, members, invites, access control — 8 files, 265 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 100 | `packages/better-auth/src/plugins/organization/organization.test.ts` | organization type; organization; invitation expiration and filtering (+14) |
| 51 | `packages/better-auth/src/plugins/organization/team.test.ts` | team; setActiveTeam org scoping; multi team support (+5) |
| 27 | `packages/better-auth/src/plugins/organization/routes/crud-org.test.ts` | get-full-organization; get-organization; organization hooks (+1) |
| 25 | `packages/better-auth/src/plugins/organization/routes/crud-access-control.test.ts` | dynamic access control |
| 23 | `packages/better-auth/src/plugins/organization/routes/crud-members.test.ts` | listMembers; listMembers with >100 members; updateMemberRole (+2) |
| 18 | `packages/better-auth/src/plugins/access/access.test.ts` | access |
| 17 | `packages/better-auth/src/plugins/organization/routes/crud-invites.test.ts` | organization invitation recipient ownership gates; invitation teamId must belong to the invitation's organization |
| 4 | `packages/better-auth/src/plugins/organization/organization-hook.test.ts` | organization creation in database hooks |

## admin-actor

Admin / impersonation / actor context — 2 files, 96 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 95 | `packages/better-auth/src/plugins/admin/admin.test.ts` | Admin plugin; access control; edge cases: userId validation (+3) |
| 1 | `packages/better-auth/src/api/middlewares/authorization.test.ts` | requireOrgRole |

## sessions

Sessions (lifetime, revocation, refresh, multi-session) — 6 files, 120 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 73 | `packages/better-auth/src/api/routes/session-api.test.ts` | session; session storage; cookie cache (+12) |
| 12 | `packages/better-auth/src/plugins/custom-session/custom-session.test.ts` **[env-gated]** | Custom Session Plugin Tests |
| 10 | `packages/better-auth/src/db/secondary-storage.test.ts` | secondary storage - get returns JSON string; secondary storage - get returns already-parsed object; secondary storage - storeSessionInDatabase (+5) |
| 10 | `packages/better-auth/src/plugins/multi-session/multi-session.test.ts` | multi-session |
| 9 | `packages/better-auth/src/api/routes/sign-out.test.ts` | sign-out |
| 6 | `test/unit/magic-link-secondary-storage.test.ts` | magic link with secondary storage (string return); magic link with secondary storage (pre-parsed object return) |

## passwords

Password hashing, rehash, rotation, pwned checks — 4 files, 76 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 38 | `packages/better-auth/src/crypto/secret-rotation.test.ts` | secret rotation; envelope format; symmetricEncrypt / symmetricDecrypt (+5) |
| 18 | `packages/better-auth/src/api/routes/password.test.ts` | forgot password; revoke sessions on password reset; verify password |
| 12 | `packages/better-auth/src/crypto/password.test.ts` | Password hashing and verification; Backward compatibility with @noble/hashes |
| 8 | `packages/better-auth/src/plugins/haveibeenpwned/haveibeenpwned.test.ts` | have-i-been-pwned; when enabled is false; reset password with email OTP (+2) |

## magic-link

Magic link, email verification, one-time tokens — 3 files, 62 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 25 | `packages/better-auth/src/api/routes/email-verification.test.ts` | Email Verification - Request body consumption bug; Email Verification; Email Verification - Timing-safe unauthenticated path (+1) |
| 23 | `packages/better-auth/src/plugins/magic-link/magic-link.test.ts` | magic link; magic link verify; magic link verify origin validation (+3) |
| 14 | `packages/better-auth/src/plugins/one-time-token/one-time-token.test.ts` | One-time token; should work with different storeToken options; hashed (+4) |

## rate-limit

Rate limiting / brute-force / lockout — 1 files, 29 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 29 | `packages/better-auth/src/api/rate-limiter/rate-limiter.test.ts` | rate-limiter; atomic concurrent enforcement; ${storage} storage (+9) |

## captcha

CAPTCHA — 1 files, 33 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 33 | `packages/better-auth/src/plugins/captcha/captcha.test.ts` | captcha; cloudflare-turnstile; google-recaptcha (+6) |

## adapters

Store adapters + schema/migration layer — 60 files, 408 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 66 | `packages/better-auth/src/db/internal-adapter.test.ts` | internal adapter test; verification token storage; verification secondary storage (+4) |
| 48 | `e2e/adapter/test/adapter-factory/adapter-factory.test.ts` | Create Adapter Helper; Checking for the results of an adapter call, as well as the parameters passed into the adapter call; create (+6) |
| 20 | `packages/better-auth/src/db/get-migration.test.ts` | get-migration: ALTER TABLE ADD COLUMN on SQLite; get-migration: compound indexes on SQLite; get-migration: unsafe schema changes on populated tables (+2) |
| 20 | `packages/core/src/db/adapter/get-id-field.test.ts` | defaultValue priority; type and required; transform.input (+3) |
| 19 | `packages/core/src/db/test/get-tables.test.ts` | getAuthTables; user.modelName collision with account schema key |
| 16 | `packages/better-auth/src/db/get-migration-schema.test.ts` | index generation for columns added to existing tables |
| 16 | `packages/drizzle-adapter/src/drizzle-adapter.test.ts` | drizzle-adapter; checkMissingFields; where field validation (+3) |
| 16 | `packages/memory-adapter/src/memory-adapter.test.ts` | memory adapter singular mutation with empty predicate; memory adapter updateMany return shape; memory adapter incrementOne (+1) |
| 16 | `packages/prisma-adapter/src/prisma-adapter.test.ts` | prisma-adapter |
| 15 | `packages/drizzle-adapter/src/relations-v2/generate-drizzle-schema.test.ts` | relations-v2 schema generator; relations part export name; schemaName (PostgreSQL namespace) |
| 15 | `packages/mongo-adapter/src/mongodb-adapter.test.ts` | mongodb-adapter; uuid support |
| 11 | `packages/redis-storage/test/redis-storage.test.ts` | redisStorage |
| 10 | `packages/core/src/context/transaction.test.ts` | runWithTransaction |
| 9 | `packages/core/src/db/database-index.test.ts` | database indexes |
| 9 | `packages/drizzle-adapter/src/join-relation-key.test.ts` | buildRelationKeysByModel; getOneToOneRelationKey |
| 7 | `packages/core/src/db/adapter/factory.test.ts` | createAdapterFactory atomic primitives; createAdapterFactory where value coercion |
| 7 | `packages/core/src/db/test/get-default-model-name.test.ts` | initGetDefaultModelName; user.modelName collision with account schema key |
| 6 | `e2e/adapter/test/drizzle-adapter/adapter.drizzle.mixed-where.test.ts` | drizzle adapter: mixed AND/OR connectors in where clauses |
| 6 | `packages/better-auth/src/db/db.test.ts` | db |
| 6 | `packages/kysely-adapter/src/with-returning-mysql.test.ts` | kysely withReturning mysql update |
| 5 | `e2e/adapter/test/drizzle-adapter/adapter.drizzle.use-plural-joins-relationname.test.ts` | drizzle adapter: usePlural + joins + ambiguous relations (#8849) |
| 5 | `e2e/adapter/test/drizzle-v2-relations-adapter/adapter.drizzle.like-escape.test.ts` | drizzle relations-v2 adapter: LIKE wildcard escaping |
| 5 | `packages/kysely-adapter/src/dialect.test.ts` | createKyselyAdapter transaction detection; D1 index introspection |
| 4 | `e2e/adapter/test/drizzle-v2-relations-adapter/adapter.drizzle.null-where.test.ts` | drizzle relations-v2 adapter: null comparisons in where clauses |
| 4 | `e2e/adapter/test/drizzle-v2-relations-adapter/adapter.drizzle.plural-query-key.test.ts` | drizzle relations-v2 adapter: plural db.query keys; drizzle relations-v2 adapter: missing relational query namespace; drizzle relations-v2 adapter: query key via relations internal |
| 4 | `packages/better-auth/src/db/to-zod.test.ts` | toZodSchema; returned: false field handling (issue #7489); required: false field nullability |
| 4 | `packages/kysely-adapter/src/increment-one.test.ts` | kysely incrementOne native |
| 4 | `packages/kysely-adapter/src/sqlite-dialect-mutations.test.ts` | NodeSqliteDialect mutation metadata; BunSqliteDialect mutation metadata |
| 4 | `packages/kysely-adapter/src/sqlite-introspector.test.ts` | sqlite introspector |
| 3 | `e2e/adapter/test/drizzle-v2-relations-adapter/adapter.drizzle.and-or-where.test.ts` | drizzle relations-v2 adapter: mixed AND/OR where clauses |
| 3 | `e2e/adapter/test/drizzle-v2-relations-adapter/adapter.drizzle.insensitive-join.test.ts` | drizzle relations-v2 adapter: case-insensitive where on the joins path |
| 3 | `e2e/adapter/test/drizzle-v2-relations-adapter/adapter.drizzle.joins-where.test.ts` | drizzle relations-v2 adapter: joins path honors insensitive mode |
| 3 | `e2e/adapter/test/drizzle-v2-relations-adapter/adapter.drizzle.like-escape-joins.test.ts` | drizzle relations-v2 adapter: LIKE escaping on the joins path |
| 3 | `packages/core/src/api/no-store.test.ts` | createAuthEndpoint metadata.noStore |
| 3 | `packages/kysely-adapter/src/kysely-adapter.test.ts` | kysely-adapter |
| 2 | `e2e/adapter/test/drizzle-adapter/adapter.drizzle.plural-joins.test.ts` | drizzle adapter: singular config.schema keys with plural db.query keys + joins |
| 2 | `e2e/adapter/test/drizzle-v2-relations-adapter/adapter.drizzle.affected-count-d1.test.ts` | drizzle relations-v2 adapter: Cloudflare D1 affected row count |
| 2 | `e2e/adapter/test/drizzle-v2-relations-adapter/adapter.drizzle.affected-count-postgres-js.test.ts` | drizzle relations-v2 adapter: postgres-js affected row count |
| 2 | `e2e/adapter/test/drizzle-v2-relations-adapter/adapter.drizzle.plural-suffix-trailing-s.test.ts` | drizzle relations-v2 adapter: join model name ending in 's' |
| 2 | `packages/better-auth/src/db/get-migration-unsafe-change.test.ts` |  |
| 1 | `e2e/adapter/test/drizzle-v2-relations-adapter/adapter.drizzle.mysql-serial-insert-id.test.ts` | drizzle relations-v2 adapter: MySQL serial insert id |
| 1 | `e2e/adapter/test/drizzle-v2-relations-adapter/adapter.drizzle.plural-one-to-one-join.test.ts` |  |
| 1 | `test/unit/no-multi-clause-adapter-update.test.ts` | adapter.update compare-and-swap lock |
| 0 | `e2e/adapter/test/drizzle-adapter/adapter.drizzle.mysql.test.ts` |  |
| 0 | `e2e/adapter/test/drizzle-adapter/adapter.drizzle.pg.test.ts` |  |
| 0 | `e2e/adapter/test/drizzle-adapter/adapter.drizzle.sqlite.test.ts` |  |
| 0 | `e2e/adapter/test/drizzle-v2-relations-adapter/adapter.drizzle.mysql.test.ts` |  |
| 0 | `e2e/adapter/test/drizzle-v2-relations-adapter/adapter.drizzle.pg.test.ts` |  |
| 0 | `e2e/adapter/test/drizzle-v2-relations-adapter/adapter.drizzle.sqlite.test.ts` |  |
| 0 | `e2e/adapter/test/kysely-adapter/adapter.kysely.custom-schema-pg.test.ts` |  |
| 0 | `e2e/adapter/test/kysely-adapter/adapter.kysely.mssql.test.ts` |  |
| 0 | `e2e/adapter/test/kysely-adapter/adapter.kysely.mysql.test.ts` |  |
| 0 | `e2e/adapter/test/kysely-adapter/adapter.kysely.pg.test.ts` |  |
| 0 | `e2e/adapter/test/kysely-adapter/adapter.kysely.sqlite.test.ts` |  |
| 0 | `e2e/adapter/test/kysely-adapter/node-sqlite-dialect.test.ts` |  |
| 0 | `e2e/adapter/test/memory-adapter/adapter.memory.test.ts` |  |
| 0 | `e2e/adapter/test/mongo-adapter/adapter.mongo-db.test.ts` |  |
| 0 | `e2e/adapter/test/prisma-adapter/prisma.mysql.test.ts` |  |
| 0 | `e2e/adapter/test/prisma-adapter/prisma.pg.test.ts` |  |
| 0 | `e2e/adapter/test/prisma-adapter/prisma.sqlite.test.ts` |  |

## engine-config

Engine, config, context, flows, identities, errors, utils — 38 files, 716 tests, scope `shared`.

| Tests | File | Suites |
| --- | --- | --- |
| 120 | `packages/better-auth/src/context/create-context.test.ts` | base context creation; secret management; session configuration (+27) |
| 77 | `packages/core/src/utils/host.test.ts` | Host Classification; Input Normalization; IPv4 Classification (+9) |
| 57 | `packages/better-auth/src/api/to-auth-endpoints.test.ts` | before hook; context; response (+13) |
| 57 | `packages/better-auth/src/utils/url.test.ts` | trimTrailingSlashes; getBaseURL; trustedProxyHeaders validation (+10) |
| 48 | `packages/better-auth/src/api/routes/account.test.ts` | account; validateUserInfo account linking; account selector validation (+2) |
| 40 | `packages/core/src/utils/ip.test.ts` | IP Normalization; isValidIP; IPv4 Normalization (+9) |
| 32 | `packages/better-auth/src/api/routes/sign-up.test.ts` | sign-up with custom fields; validateUserInfo sign-up; sign-up user enumeration protection (+5) |
| 28 | `packages/better-auth/src/api/routes/update-user.test.ts` | updateUser; delete user; change-email enumeration protection (+5) |
| 25 | `packages/better-auth/src/types/types.test.ts` | general types; plugin types through factory and indirection patterns; public type exports (+2) |
| 24 | `packages/better-auth/src/api/routes/sign-in.test.ts` | sign-in; url checks; sign-in CSRF protection (+3) |
| 20 | `packages/better-auth/src/call.test.ts` | call |
| 20 | `packages/core/src/utils/url.test.ts` | appendQueryParams; isSafeUrlScheme; normalizePathname (+2) |
| 19 | `packages/better-auth/src/plugins/test-utils/test-utils.test.ts` | testUtils plugin; basic functionality; user factories (+5) |
| 15 | `packages/better-auth/src/auth/full.test.ts` | auth type; auth with trusted proxy headers; auth with dynamic baseURL (allowedHosts) |
| 14 | `test/unit/types/endpoint-method.test.ts` | Endpoint method types; Generic OAuth types; Plugin endpoint override types (+1) |
| 13 | `packages/better-auth/src/api/check-endpoint-conflicts.test.ts` | checkEndpointConflicts |
| 12 | `packages/core/src/utils/async.test.ts` | mapConcurrent |
| 11 | `packages/better-auth/src/plugins/additional-fields/additional-fields.test.ts` | additionalFields; runtime |
| 10 | `test/unit/types/db.test.ts` |  |
| 9 | `packages/better-auth/src/api/index.test.ts` | getEndpoints; onRequest chain; skipTrailingSlashes option (+1) |
| 8 | `packages/core/src/context/request-state.test.ts` | request-state; runWithRequestState; hasRequestState (+2) |
| 6 | `packages/better-auth/src/auth/minimal.test.ts` | auth-minimal |
| 6 | `packages/better-auth/src/context/init.test.ts` | init (with Kysely) |
| 5 | `packages/core/src/env/logger.test.ts` | shouldPublishLog; logger |
| 5 | `packages/core/src/utils/deprecate.test.ts` | deprecate |
| 5 | `packages/core/src/utils/string.test.ts` | capitalizeFirstLetter; toSnakeCase; toKebabCase (+2) |
| 4 | `packages/better-auth/src/api/server-only-endpoints.test.ts` | server-only endpoints |
| 4 | `packages/core/src/env/env-impl.test.ts` | cross-runtime production detection |
| 3 | `packages/better-auth/src/context/init-minimal.test.ts` | init-minimal (without Kysely) |
| 3 | `packages/core/src/context/endpoint-context.test.ts` | runWithEndpointContext; getCurrentAuthEndpointContext |
| 3 | `packages/core/src/utils/email.test.ts` | createPlaceholderEmail |
| 3 | `packages/core/src/utils/fetch-metadata.test.ts` | isBrowserFetchRequest |
| 2 | `packages/better-auth/src/api/routes/error.test.ts` | error page security |
| 2 | `packages/better-auth/src/test-utils/test-instance.test.ts` | getTestInstance password hasher |
| 2 | `test/unit/proxy-agent/index.spec.ts` | ProxyAgent with better-auth OAuth |
| 2 | `test/unit/types/index.test.ts` |  |
| 1 | `packages/better-auth/src/utils/request.test.ts` | safeCloneRequest |
| 1 | `test/unit/oauth-stateless-account-data.test.ts` | stateless mode account_data cookie (issue #9375) |

