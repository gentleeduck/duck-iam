import type { OAuthClient } from './client'

export namespace OAuth {
  /** OIDC/oauth2 endpoints, given directly for a known provider or resolved by discovery for a generic issuer. */
  export type Endpoints = {
    authorizationEndpoint: string
    tokenEndpoint: string
    /** OIDC userinfo. Optional: providers often expose a bespoke profile endpoint instead. */
    userinfoEndpoint?: string
    /** OIDC revocation (optional). */
    revocationEndpoint?: string
  }

  export type ClientOptions = {
    clientId: string
    clientSecret?: string
    /** Per-request `client_secret`, called on every exchange and refresh. For Sign in with Apple. Wins over
     *  `clientSecret`. */
    dynamicClientSecret?: () => string | Promise<string>
    /** Can be promised, for discovery at boot. */
    endpoints: Endpoints | (() => Promise<Endpoints>)
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

  /** The one profile shape every provider maps its own userinfo, id_token or bespoke endpoint onto. */
  export interface Profile {
    /** Stable subject identifier at the provider (OIDC `sub`). */
    sub: string
    email?: string
    emailVerified?: boolean
    name?: string
    avatarUrl?: string
  }

  /** Extended by every provider-specific options interface: Google, GitHub, Apple, Discord and the rest. */
  export interface OptionsBase<AppProfile = unknown> {
    /** oauth client id assigned by the IdP. */
    clientId: string
    /** Client secret. Confidential clients (server-side) only. */
    clientSecret: string
    /** Exact callback URL registered with the IdP. Must match. */
    redirectUri: string
    /** Per-AuthEngine signing secret for the oauth `state` parameter. */
    stateSigningSecret: string
    /** Binds a callback to the browser that began the flow. See {@link OAuth.StateCookie}. */
    stateCookie?: StateCookie
    /** Overrides the provider's default scopes. */
    scopes?: string[]
    /** Override fetch impl (test stubs). */
    fetch?: typeof globalThis.fetch
    /** Customise identity resolution at signin time. */
    onSignIn?: Options<AppProfile>['onSignIn']
    /** Project canonical Profile into the consumer's Profile shape. */
    profileToIdentityProfile?: Options<AppProfile>['profileToIdentityProfile']
    /** What to do when the profile's email already belongs to an identity with no link to this provider. See
     *  {@link OAuth.Options.onFederationConflict}; the default is `'reject'`. */
    onFederationConflict?: Options<AppProfile>['onFederationConflict']
  }

  /** The pre-auth cookie's own settings. `secure` defaults to true and the name to `__Host-duck-oauth`, which
   *  the browser only accepts over https, so an http development host has to name both. */
  export interface StateCookie {
    name?: string
    secure?: boolean
    domain?: string
  }

  /** Full options surface consumed by `oProvider`. */
  export interface Options<AppProfile = unknown> {
    /** Stable id, which the library prefixes with `oauth:`. */
    providerId: string
    client: OAuthClient
    endpoints: Endpoints | (() => Promise<Endpoints>)
    redirectUri: string
    /** Secret used to sign the oauth `state` parameter. */
    stateSigningSecret: string
    /** Binds a callback to the browser that began the flow. See {@link OAuth.StateCookie}. */
    stateCookie?: StateCookie
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
     * What to do when the profile's email matches an identity that has no link to this provider yet. Defaults to
     * `'reject'`, because a provider that does not verify the address makes this account takeover by squatting.
     */
    onFederationConflict?: FederationPolicy
  }

  /** Policy + hook shape for the federation conflict workflow. */
  export type FederationPolicy =
    | 'reject'
    | 'link-if-verified'
    | ((ctx: { existingIdentityId: string; profile: Profile; providerId: string }) => Promise<'link' | 'reject'>)

  export interface BeginInput {
    /**
     * Carried through the signed state and handed back to nothing: `complete` answers with
     * `clearCookie` + `startSession`, so the post-login redirect is still the host's to perform.
     *
     * SECURITY: if this ever becomes a `redirect` intent it has to go through `isSafeCallbackPath`
     * first. The value reaches the state from whatever the host passed to `begin`, which is normally
     * a query parameter, and the signature proves only that this library minted it - an attacker who
     * calls `begin` themselves gets a signed state for any target they like. `parseStatePayload`
     * caps the length and nothing else.
     */
    returnTo?: string
  }

  export interface CompleteInput {
    /** Authorisation code returned by the provider. */
    code: string
    /** Opaque state value the library issued at begin. */
    state: string
    /** The callback request's `Cookie` header, verbatim.
     *  SECURITY: without it the signed state verifies from any browser, so an attacker completes their own
     *  flow, hands over the callback URL, and the victim signs in as the attacker. */
    cookieHeader?: string
  }

  /** Shape stored in `Credential.metadata` for oauth credentials. */
  export interface CredentialMetadata {
    provider: string
    sub: string
    familyId: string
    generation: number
  }

  /** Signed `state` payload, `<payload-base64url>.<sig-base64url>` under HMAC-SHA256 with the engine's signing
   *  secret. Carries the PKCE verifier and the digest of the cookie `begin` left in the browser, so one
   *  authorisation code cannot be stitched to another flow. */
  export interface StatePayload {
    /** Random nonce; one-time use. */
    nonce: string
    /** PKCE verifier. Secret; never leaves the server. */
    verifier: string
    /** Provider id; library refuses if it doesn't match the callback. */
    providerId: string
    /** Digest of the value `begin` set as a cookie. The state is signed but not secret, travelling through the
     *  IdP in a URL, so the cookie is what proves the callback reached the browser that started the flow. */
    binding: string
    /** Optional return-to path on the app, as `begin` minted it. Round-tripped and length-capped, never
     *  read after that - see `BeginInput.returnTo`. */
    returnTo?: string
    /** Issued-at; signer rejects after `maxAgeMs`. Default 10 minutes. */
    iat: number
  }

  /** Refresh-token family metadata, kept on the `kind: 'oauth'` credential and rotated atomically by
   *  `authRefreshoauthToken`. Reusing an old refresh token throws `AUTH_OAUTH_REUSE_DETECTED` and revokes
   *  the whole family. */
  export interface FamilyMetadata {
    provider: string
    sub: string
    familyId: string
    generation: number
    /** When set, family revoked; every member rejects on lookup. */
    revokedAt?: number
    /** Index signature for Credential.metadata assignment. */
    [k: string]: unknown
  }

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
    /** `common` (any AAD tenant plus personal accounts), `organizations`, `consumers`, or a tenant GUID.
     *  Default `common`. */
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

  /** Apple-specific options. `clientSecret` from {@link OAuth.OptionsBase} is ignored: the secret is minted per
   *  request from the team, key and private-key triple. */
  export interface AppleOptions<AppProfile = unknown> extends Omit<OptionsBase<AppProfile>, 'clientSecret'> {
    /** Apple Developer Team ID (10-char alphanumeric). */
    teamId: string
    /** Key ID associated with the AuthKey_*.p8 file. */
    keyId: string
    /** The contents of the AuthKey_*.p8 file, an ES256 private key in PEM. Load it from a secrets manager. */
    privateKey: string
    /** Default `['name', 'email']`. */
    scopes?: string[]
  }
}
