import type { OAuthClient } from './client'

/**
 * Every shared type the oauth stack exposes lives under this one namespace, so
 * consumers reach for `OAuth.Options`, `OAuth.Endpoints`, `OAuth.GoogleOptions`,
 * etc. from a single place. The runtime `OAuthClient` class lives in
 * `./client`; refresh/state/provider helpers keep their function names.
 */
export namespace OAuth {
  // --- client ------------------------------------------------------------

  /**
   * OIDC / oauth2 endpoints. Supplied directly (Google, GitHub, static
   * well-known providers) or resolved at runtime via discovery for generic
   * OIDC issuers.
   */
  export type Endpoints = {
    authorizationEndpoint: string
    tokenEndpoint: string
    /** OIDC userinfo (optional - providers often expose a profile endpoint instead). */
    userinfoEndpoint?: string
    /** OIDC revocation (optional). */
    revocationEndpoint?: string
  }

  /** Cfg knobs for the `OAuthClient`. */
  export type ClientOptions = {
    clientId: string
    clientSecret?: string
    /**
     * Per-request client_secret generator. When provided, called on
     * every exchangeCode / refresh and used as `client_secret` in the
     * form body. Designed for Sign in with Apple. Takes precedence
     * over `clientSecret`.
     */
    dynamicClientSecret?: () => string | Promise<string>
    /** Endpoints; can be promised when discovering at boot. */
    endpoints: Endpoints | (() => Promise<Endpoints>)
    /** oauth2 scopes the provider should request. */
    scopes: string[]
    /** Override the fetch impl (test stubs). */
    fetch?: typeof globalThis.fetch
  }

  /** Standard oauth2 token-endpoint response. */
  export type TokenResponse = {
    access_token: string
    token_type: string
    expires_in?: number
    refresh_token?: string
    id_token?: string
    scope?: string
  }

  // --- provider ----------------------------------------------------------

  /**
   * Canonical profile shape after a provider extracts it from
   * userinfo / id_token / provider-specific endpoint. Providers
   * (google, github, ...) map their idiosyncratic field names to this shape.
   */
  export interface Profile {
    /** Stable subject identifier at the provider (OIDC `sub`). */
    sub: string
    email?: string
    emailVerified?: boolean
    name?: string
    avatarUrl?: string
  }

  /**
   * Shared option surface every provider-specific oauth options interface
   * (Google / GitHub / Apple / Discord / ...) extends.
   */
  export interface OptionsBase<AppProfile = unknown> {
    /** oauth client id assigned by the IdP. */
    clientId: string
    /** Client secret. Confidential clients (server-side) only. */
    clientSecret: string
    /** Exact callback URL registered with the IdP. Must match. */
    redirectUri: string
    /** Per-AuthEngine signing secret for the oauth `state` parameter. */
    stateSigningSecret: string
    /** Override IdP scopes; falls back to provider default. */
    scopes?: string[]
    /** Override fetch impl (test stubs). */
    fetch?: typeof globalThis.fetch
    /** Customise identity resolution at signin time. */
    onSignIn?: Options<AppProfile>['onSignIn']
    /** Project canonical Profile into the consumer's Profile shape. */
    profileToIdentityProfile?: Options<AppProfile>['profileToIdentityProfile']
  }

  /** Full options surface consumed by `oProvider`. */
  export interface Options<AppProfile = unknown> {
    /** Stable id; library prefixes with `oauth:` for consistency. */
    providerId: string
    client: OAuthClient
    endpoints: Endpoints | (() => Promise<Endpoints>)
    /** Redirect URI registered with the provider. */
    redirectUri: string
    /** Secret used to sign the oauth `state` parameter. */
    stateSigningSecret: string
    /** Extract a canonical profile from the token response + userinfo. */
    fetchProfile: (tokens: { access_token: string; id_token?: string }, client: OAuthClient) => Promise<Profile>
    /** Map Profile -> consumer Profile shape on first sign-in. */
    profileToIdentityProfile?: (p: Profile) => AppProfile
    /** Identity-resolution override; null return refuses sign-in. */
    onSignIn?: (ctx: {
      profile: Profile
      findByProviderSub: (providerSub: string) => Promise<{ id: string } | null>
      findByEmail: (email: string) => Promise<{ id: string } | null>
      createIdentity: (profile: AppProfile) => Promise<{ id: string }>
      linkProvider: (identityId: string, providerSub: string) => Promise<void>
    }) => Promise<{ identityId: string } | null>
    /**
     * Federation conflict policy. Fires when the oauth profile's email
     * matches an existing identity but no matching provider-sub link exists
     * yet. The default behaviour is `'reject'` - the safest pre-1.1 stance,
     * because oauth providers that do NOT mark the email as verified would
     * otherwise enable account-takeover via email squatting.
     *
     * - `'reject'`: throw `AUTH/PROVIDER_FAILED` with detail `federation-conflict`.
     * - `'link-if-verified'`: link the new provider IFF the oauth profile's
     *   `email_verified` claim is true; otherwise reject.
     * - `(ctx) => Promise<'link' | 'reject'>`: caller-supplied hook for
     *   "merge-after-confirmation" - the app prompts the user out-of-band and
     *   resolves with the verdict.
     */
    onFederationConflict?: FederationPolicy
  }

  /** Policy + hook shape for the federation conflict workflow. */
  export type FederationPolicy =
    | 'reject'
    | 'link-if-verified'
    | ((ctx: { existingIdentityId: string; profile: Profile; providerId: string }) => Promise<'link' | 'reject'>)

  /** Input to {@link oProvider}.begin. */
  export interface BeginInput {
    /** Optional return-to path; library appends to the front-end after callback. */
    returnTo?: string
  }

  /** Input to {@link oProvider}.complete. */
  export interface CompleteInput {
    /** Authorisation code returned by the provider. */
    code: string
    /** Opaque state value the library issued at begin. */
    state: string
  }

  /** Shape stored in `Credential.metadata` for oauth credentials. */
  export interface CredentialMetadata {
    provider: string
    sub: string
    familyId: string
    generation: number
    accessToken?: string
    /** Epoch ms when the access token expires. */
    accessTokenExpiresAt?: number
  }

  // --- state -------------------------------------------------------------

  /**
   * Signed `state` parameter payload. Carries the PKCE verifier + an opaque
   * nonce tied to the user's pre-auth cookie so an attacker cannot stitch a
   * stolen authorisation code to a different browser.
   *
   * Encoding: `<payload-base64url>.<sig-base64url>`. HMAC-SHA256 over the
   * payload with the per-AuthEngine signing secret.
   */
  export interface StatePayload {
    /** Random nonce; one-time use. */
    nonce: string
    /** PKCE verifier - secret. Never leaves the server. */
    verifier: string
    /** Provider id; library refuses if it doesn't match the callback. */
    providerId: string
    /** Optional return-to path on the app. */
    returnTo?: string
    /** Issued-at; signer rejects after `maxAgeMs`. Default 10 minutes. */
    iat: number
  }

  // --- refresh -----------------------------------------------------------

  /**
   * Refresh-token family metadata. Persisted under `kind: 'oauth'` credentials
   * by the oauth provider at signin; rotated atomically by
   * {@link authRefreshoauthToken}. Reuse of an old refresh token causes a
   * `AUTH/oauth/REUSE_DETECTED` throw + revocation of the whole token family.
   */
  export interface FamilyMetadata {
    provider: string
    sub: string
    familyId: string
    generation: number
    accessToken: string
    accessTokenExpiresAt?: number
    /** When set, family revoked; every member rejects on lookup. */
    revokedAt?: number
    /** Index signature for Credential.metadata assignment. */
    [k: string]: unknown
  }

  // --- vendors -----------------------------------------------------------

  /** Google-specific options. Default scopes `['openid', 'email', 'profile']`. */
  export interface GoogleOptions<AppProfile = unknown> extends OptionsBase<AppProfile> {
    scopes?: string[]
  }

  /** GitHub-specific options. Default scopes `['read:user', 'user:email']`. */
  export interface GithubOptions<AppProfile = unknown> extends OptionsBase<AppProfile> {
    scopes?: string[]
  }

  /** Microsoft Entra ID-specific options. */
  export interface MicrosoftOptions<AppProfile = unknown> extends OptionsBase<AppProfile> {
    /**
     * Tenant: `common` (any AAD tenant + personal accounts),
     * `organizations` (any AAD tenant), `consumers` (personal only),
     * or a specific tenant GUID. Default `common`.
     */
    tenant?: string
    /** Default `['openid', 'profile', 'email', 'User.Read']`. */
    scopes?: string[]
  }

  /** Discord-specific options. Default scopes `['identify', 'email']`. */
  export interface DiscordOptions<AppProfile = unknown> extends OptionsBase<AppProfile> {
    scopes?: string[]
  }

  /** LinkedIn-specific options. Default scopes `['openid', 'profile', 'email']`. */
  export interface LinkedinOptions<AppProfile = unknown> extends OptionsBase<AppProfile> {
    scopes?: string[]
  }

  /**
   * Apple-specific options. `clientSecret` from `OptionsBase` is ignored; the
   * secret is generated per request from the team / key / private-key triple.
   */
  export interface AppleOptions<AppProfile = unknown> extends Omit<OptionsBase<AppProfile>, 'clientSecret'> {
    /** Apple Developer Team ID (10-char alphanumeric). */
    teamId: string
    /** Key ID associated with the AuthKey_*.p8 file. */
    keyId: string
    /**
     * The contents of the AuthKey_*.p8 file (ES256 private key, PEM).
     * Treat as a secret; load from a secrets manager.
     */
    privateKey: string
    /** Default `['name', 'email']`. */
    scopes?: string[]
  }
}
