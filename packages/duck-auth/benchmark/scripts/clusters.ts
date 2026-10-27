/**
 * Feature clusters: the vocabulary both suites get mapped onto.
 *
 * A cluster is matched against a test file's path relative to its repo root,
 * most specific first, and the first match wins — so order here IS precedence.
 *
 * WARN: paths have no leading slash, so a pattern must open with `(^|/)`, never
 * `/x/`. A bare `/plugin/` also swallows all of better-auth's `src/plugins/*`,
 * which silently emptied six clusters on the first run of this script.
 *
 * `scope` records whether the capability is in scope for duck-auth at all, so a
 * zero is never read as a missing test when it is a deliberate boundary.
 */

export type Scope =
  /** Both libraries implement it; a count difference is a real coverage difference. */
  | 'shared'
  /** better-auth implements it, duck-auth deliberately does not. */
  | 'ba-only-by-design'
  /** better-auth implements it, duck-auth does not, and arguably should. */
  | 'ba-only-gap'
  /** duck-auth implements it, better-auth has no counterpart. */
  | 'duck-only'

export interface Cluster {
  key: string
  label: string
  scope: Scope
  patterns: RegExp[]
  note?: string
}

/** `(^|/)name/` — a directory segment anywhere in the path. */
const dir = (name: string) => new RegExp(`(^|/)${name}/`)
/** `(^|/)stem` — a path segment that starts with this stem. */
const seg = (stem: string) => new RegExp(`(^|/)${stem}`)

export const CLUSTERS: Cluster[] = [
  // ---------------------------------------------------------------------------
  // Named features first. Anything that is a distinct capability must be
  // claimed before the broad engine/plumbing cluster at the bottom.
  // ---------------------------------------------------------------------------
  {
    key: 'scim',
    label: 'SCIM provisioning',
    scope: 'ba-only-gap',
    patterns: [dir('scim'), seg('scim')],
  },
  {
    key: 'billing',
    label: 'Billing / Stripe',
    scope: 'ba-only-by-design',
    patterns: [dir('stripe')],
    note: 'Out of scope: duck-auth is not a billing library.',
  },
  {
    key: 'cli',
    label: 'CLI, codegen, release tooling',
    scope: 'ba-only-gap',
    patterns: [dir('cli'), dir('release-tooling')],
  },
  {
    key: 'mcp',
    label: 'MCP server auth',
    scope: 'ba-only-gap',
    patterns: [dir('mcp'), seg('mcp-'), /mcp\.test/, /require-mcp-auth/],
  },
  {
    key: 'cimd',
    label: 'CIMD (client identity metadata documents)',
    scope: 'ba-only-gap',
    patterns: [dir('cimd'), /cimd\./, /validate-metadata-document/, /fetch-governor/],
  },
  {
    key: 'i18n',
    label: 'i18n / localised messages',
    scope: 'ba-only-gap',
    patterns: [dir('i18n')],
  },
  {
    key: 'telemetry',
    label: 'Telemetry + instrumentation',
    scope: 'ba-only-gap',
    patterns: [dir('telemetry'), /instrumentation/],
  },
  {
    key: 'openapi',
    label: 'OpenAPI spec generation',
    scope: 'ba-only-by-design',
    patterns: [/open-api/, /openapi/],
    note: 'Removed with the route layer in PR #288.',
  },
  {
    key: 'runtime-smoke',
    label: 'Runtime + bundler smoke (bun/deno/CF/esbuild/vite/tsconfig)',
    scope: 'ba-only-gap',
    patterns: [dir('smoke')],
  },
  {
    key: 'email-otp',
    label: 'Email OTP / phone (SMS) OTP sign-in',
    scope: 'ba-only-gap',
    patterns: [/email-otp/, /phone-number/],
  },
  {
    key: 'device-auth',
    label: 'Device authorization grant (RFC 8628)',
    scope: 'ba-only-gap',
    patterns: [/device-authorization/, /device-code/],
  },
  {
    key: 'username-anon',
    label: 'Username provider, anonymous auth, last-login-method',
    scope: 'ba-only-gap',
    patterns: [/username/, dir('anonymous'), /anon\.test/, /last-login-method/, /custom-prefix/],
  },
  {
    key: 'client',
    label: 'Client SDK (vanilla + react/vue/solid/svelte + expo/electron)',
    scope: 'ba-only-by-design',
    patterns: [
      dir('client'),
      dir('expo'),
      dir('electron'),
      dir('lynx'),
      // Segment-anchored: `saml-unsigned-client.test.ts` is a SAML test, not a client-SDK one.
      /(^|\/)client\.test/,
      /client-declaration/,
      /client-ssr/,
      /client-store/,
      /\.client\.test/,
      /session-refresh/,
      /broadcast-channel/,
      /focus-manager/,
      /online-manager/,
      /session-atom/,
    ],
    note: 'duck-auth removed every client binding in PR #288; apps bring their own fetch.',
  },
  {
    key: 'frameworks-client',
    label: 'Framework integration, browser-driven (Playwright)',
    scope: 'ba-only-by-design',
    patterns: [/next-js\.test/, dir('integration')],
    note: 'duck-auth ships no routes or handlers, so there is no mounted app to drive.',
  },

  // ---- duck-auth-only capabilities ----
  {
    key: 'anomaly',
    label: 'Anomaly detection, device fingerprint, impossible travel, hijack',
    scope: 'duck-only',
    patterns: [dir('anomaly'), dir('hijack'), /device-fingerprint/, /impossible-travel/],
  },
  {
    key: 'data-at-rest',
    label: 'Encryption at rest (AES-GCM, KMS envelope)',
    scope: 'duck-only',
    patterns: [dir('dataAtRest'), /aes-gcm/, /kms-envelope/, /aws-kms/],
  },
  {
    key: 'webhooks-events',
    label: 'Webhooks + event delivery / audit bus',
    scope: 'duck-only',
    patterns: [dir('webhooks'), dir('events'), /webhooks-/, /events\./, /resubscribe-race/, /audit-actor/],
  },
  {
    key: 'idempotency',
    label: 'Idempotency keys',
    scope: 'duck-only',
    patterns: [/idempotency/],
  },
  {
    key: 'tenancy',
    label: 'Multi-tenancy scoping',
    scope: 'duck-only',
    patterns: [dir('tenant'), /tenant/],
  },
  {
    key: 'm2m',
    label: 'Machine-to-machine grants',
    scope: 'duck-only',
    patterns: [dir('m2m'), /m2m-/],
  },
  {
    key: 'compliance-presets',
    label: 'Compliance presets + capability matrix',
    scope: 'duck-only',
    patterns: [dir('compliance'), /compliance-presets/],
  },
  {
    key: 'frameworks-server',
    label: 'Server framework adapters (hono/express/fastify/koa/elysia/nest/next/grpc)',
    scope: 'duck-only',
    patterns: [
      dir('server'),
      dir('hono'),
      dir('express'),
      dir('fastify'),
      dir('koa'),
      dir('elysia'),
      dir('nestjs'),
      dir('next'),
      dir('grpc'),
      dir('generic'),
      /actor-context/,
      /request-security/,
      /guard-csrf-parity/,
      /adapters-caller/,
      /caller-context/,
    ],
    note: 'better-auth has one handler for every framework, so it has nothing per-framework to test.',
  },

  // ---- shared capabilities ----
  {
    key: 'saml-sso',
    label: 'SAML + SSO provider registry',
    scope: 'shared',
    patterns: [
      dir('sso'),
      dir('saml'),
      /saml[.-]/,
      /domain-verification/,
      /org-assignment/,
      /user-resolution/,
      /provider-(lock|reference)/,
      /(^|\/)providers\.test/,
      /(^|\/)discovery\.test/,
      // Qualified: `core/oauth2/verify-id-token.test.ts` is an OAuth2 concern, not SSO.
      /sso\/.*id-token\.test/,
    ],
  },
  {
    key: 'oidc-op',
    label: 'OIDC provider (authorize/token/DCR/introspect/resources)',
    scope: 'shared',
    patterns: [
      dir('oauth-provider'),
      dir('oidc'),
      dir('oauthClient'),
      dir('oauthConsent'),
      dir('oauthResource'),
      /oidc-op/,
      /oidc\./,
      /(^|\/)(authorize|token|introspect|revoke|userinfo|register|metadata|claims|logout|pairwise|extensions)\.test/,
      /backchannel-logout/,
      /claim-authority/,
      /private-key-jwt/,
      /pkce-optional/,
      /resource-(binding|challenge|discovery)/,
      /resources(-e2e)?\.test/,
      /oauth-endpoint/,
      // Qualified: a bare /oauth\.test/ also claims duck-auth's OAuth *client* suite.
      /oauth-provider\/oauth\.test/,
      /signed-query/,
      /validation-flow/,
      /query-serialization/,
      /client-jwks/,
      /client-resource/,
      /rfc-(conformance|token-conformance)/,
      /\bdcr\b/,
      /timestamps\.test/,
    ],
  },
  {
    key: 'transport',
    label: 'Transport: cookies, bearer, JWT, DPoP, CSRF, origin',
    scope: 'shared',
    patterns: [
      dir('transport'),
      dir('cookies'),
      dir('csrf'),
      dir('jwt'),
      dir('bearer'),
      /cookies?\./,
      /cookie-cache/,
      /bearer[.-]/,
      /jwt[.-]/,
      /csrf[.-]/,
      /origin-check/,
      /trusted-origins/,
      /dpop/,
      /multi-alg/,
      /(^|\/)rotation\.test/,
      /sign-overrides/,
      /transport-verdict/,
    ],
  },
  {
    key: 'oauth-social',
    label: 'OAuth2 client + social providers',
    scope: 'shared',
    patterns: [
      dir('oauth'),
      dir('oauth2'),
      dir('social-providers'),
      dir('apple'),
      dir('github'),
      dir('microsoft'),
      /generic-oauth/,
      /oauth-proxy/,
      /oauth-popup/,
      /one-tap/,
      dir('siwe'),
      /siwe\./,
      /social\.test/,
      /link-account/,
      /account-key/,
      /federation-conflict/,
      /userinfo-extractors/,
      /outbound-redirects/,
      /(^|\/)state\.test/,
    ],
  },
  {
    key: 'passkey',
    label: 'Passkey / WebAuthn',
    scope: 'shared',
    patterns: [dir('passkey'), /passkey[.-]/, /authenticator-metadata/, /challenge-store/],
  },
  {
    key: 'mfa',
    label: 'MFA: TOTP, backup codes, step-up',
    scope: 'shared',
    patterns: [/two-factor/, dir('mfa'), /mfa[.-]/, /totp/, /backup-code/, /stepup/, /step-up/, /remember-me/, /otpauth/],
  },
  {
    key: 'api-key',
    label: 'API keys',
    scope: 'shared',
    patterns: [dir('api-key'), /api-key/, /apikeys/],
  },
  {
    key: 'orgs',
    label: 'Organizations, teams, members, invites, access control',
    scope: 'shared',
    patterns: [
      dir('organization'),
      dir('orgs'),
      /orgs[.-]/,
      /organization/,
      /(^|\/)team\./,
      dir('access'),
      /(^|\/)access\.test/,
      /crud-(org|members|invites|access)/,
    ],
  },
  {
    key: 'admin-actor',
    label: 'Admin / impersonation / actor context',
    scope: 'shared',
    patterns: [dir('admin'), dir('actor'), /actor\./, /impersonate/, /(^|\/)authorization\.test/],
  },
  {
    key: 'sessions',
    label: 'Sessions (lifetime, revocation, refresh, multi-session)',
    scope: 'shared',
    patterns: [
      dir('sessions'),
      /sessions[.-]/,
      /session-api/,
      /multi-session/,
      /session-security/,
      /sliding-session/,
      /secondary-storage/,
      /resolve-session/,
      /custom-session/,
      /active-devices/,
      /expiry-(is-not|cleanup)/,
      /freshness-window/,
      /revocation\./,
      /sign-out/,
    ],
  },
  {
    key: 'passwords',
    label: 'Password hashing, rehash, rotation, pwned checks',
    scope: 'shared',
    patterns: [
      dir('passwords'),
      dir('hashers'),
      dir('crypto'),
      /password/,
      /secret-rotation/,
      /haveibeenpwned/,
      /hasher/,
      /argon2/,
      /scrypt/,
      /crypto\.test/,
    ],
  },
  {
    key: 'magic-link',
    label: 'Magic link, email verification, one-time tokens',
    scope: 'shared',
    patterns: [/magic-link/, /one-time-token/, /email-verification/, /one-shot-credentials/, /token-quality/, /deletion-undo-token/],
  },
  {
    key: 'rate-limit',
    label: 'Rate limiting / brute-force / lockout',
    scope: 'shared',
    patterns: [/rate-limit/, dir('limiters'), /limiter/, /brute-force/, /lockout/, /attempt-cap/],
  },
  {
    key: 'captcha',
    label: 'CAPTCHA',
    scope: 'shared',
    patterns: [dir('captcha'), /captcha/],
  },
  {
    key: 'adapters',
    label: 'Store adapters + schema/migration layer',
    scope: 'shared',
    patterns: [
      dir('adapters'),
      dir('adapter'),
      /(drizzle|kysely|memory|mongo|prisma)-adapter/,
      /redis-storage/,
      /adapter[.-]/,
      /internal-adapter/,
      dir('db'),
      dir('drivers'),
      /get-migration/,
      /adapter-factory/,
      /database-index/,
      /get-tables/,
      /get-id-field/,
      /get-default-model-name/,
      /to-zod/,
      /dialect-contract/,
      /\.schema\.test/,
      /stored-json/,
      /foreign-keys-ready/,
      /sqlite\./,
      /valkey/,
      /redis-like/,
      /redis-parser/,
      /async-driver/,
      /identifier-folding/,
      /declared-range/,
      /patch-metadata-stress/,
      /find-by-/,
      /create-with-providers-toctou/,
      /(^|\/)rows\.test/,
      /mysql-driver-shape/,
      /no-store/,
      /(^|\/)transaction/,
      /(^|\/)constraints/,
    ],
  },

  // ---------------------------------------------------------------------------
  // Everything left: the engine, its config, and shared plumbing. Deliberately
  // last, because a broad pattern here would eat a named feature above.
  // ---------------------------------------------------------------------------
  {
    key: 'engine-config',
    label: 'Engine, config, context, flows, identities, errors, utils',
    scope: 'shared',
    patterns: [/./],
  },
]

/** First matching cluster wins, so order in CLUSTERS is the precedence. */
export function classify(relPath: string): Cluster | undefined {
  return CLUSTERS.find((c) => c.patterns.some((p) => p.test(relPath)))
}
