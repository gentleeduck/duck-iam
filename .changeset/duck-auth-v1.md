---
'@gentleduck/auth': major
---

# @gentleduck/auth 1.0

First stable release. This version cuts the "0.x means anything can change" window and commits to the public surface.

## New features

- **`@gentleduck/auth/oidc/op`** - full OAuth2 / OIDC Provider:
  - `/authorize` with mandatory S256 PKCE
  - `/token` with `authorization_code` and `refresh_token` grants; refresh-token rotation with family-revoke on reuse detection
  - `/userinfo` with scope-gated profile / email claims
  - `/introspect` (RFC 7662) and `/revoke` (RFC 7009)
  - `/register` (RFC 7591 Dynamic Client Registration) with `initialAccessToken` gate
  - Constant-time client-secret compare; sha256-at-rest for codes, access tokens, refresh tokens, client secrets
- **`@gentleduck/auth/oidc/op/drizzle/{pg,sqlite,mysql}`** - production-grade Drizzle stores for the OP. Five tables per dialect: clients, codes, access tokens, refresh tokens, consents. Cross-dialect schema parity verified.
- **`@gentleduck/auth/providers/saml`** - expanded scope:
  - `buildSpMetadata({ client?, metadata })` - SP metadata XML generation
  - `samlSloController({ client })` - Single Logout with SP-initiated, IdP-initiated, and POST/Redirect binding methods
  - IdP-initiated SSO documented (the existing `complete()` already accepted unsolicited assertions)
- **`defineAuth`** factory now accepts a strongly-typed `IPluginEntry<Profile, Tenant, OrgMeta>` array - the previous `any` plugin shape is gone.
- **`@gentleduck/auth/core/transport`** - JWT signing / verifying is now split per-algorithm. HS256 / RS256 / ES256 / EdDSA each live in their own module under `transport/jwt-algs/`.

## Internal refactors

- `core/facets/flows.ts` split into seven dedicated modules under `core/facets/flows/`: password-reset, email-verification, account-deletion, signup, impersonate, provider-link. Public class API unchanged.
- `transport/jwt.ts` algorithm dispatch is now a thin switch over the four jwt-algs modules.
- 88 new tests across the new modules + 47 OIDC RFC conformance tests + 29 SAML metadata XSD-shape tests + 12 static-analysis security tests.

## Documentation

- `THREAT-MODEL.md` extended with OIDC OP-specific and SAML SP-specific threat sections.
- `AUDIT-RESULTS.md` checked in (0 runtime advisories; 7 dev-tooling-only).
- Static-analysis suite at `src/__tests__/static-analysis.test.ts` enforces source-tree-level security invariants (no `Math.random` in security paths, no `===` on secret-named fields, constant-time compares, etc.).

## Migration

No breaking API changes vs 0.2.0; new exports are additive. The `IPluginEntry` type went from `any | false | null | undefined | ''` to the discriminated union - consumers passing properly-shaped plugin objects need no change.
