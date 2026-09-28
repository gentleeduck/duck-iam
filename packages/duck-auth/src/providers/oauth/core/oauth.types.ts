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

  /** The client credentials and endpoints an `OAuthClient` talks to. */
  export type ClientOptions = {
    /** The client id the provider issued. */
    clientId: string
    /** Absent for a PKCE public client. */
    clientSecret?: string
    /** Per-request `client_secret`, called on every exchange and refresh. For Sign in with Apple. Wins over
     *  `clientSecret`. */
    dynamicClientSecret?: () => string | Promise<string>
    /** Can be promised, for discovery at boot. */
    endpoints: Endpoints | (() => Promise<Endpoints>)
    /** Requested at authorize time. */
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
    /** Burns the state's nonce at `complete`. See {@link OAuth.Options.nonceStore}. */
    nonceStore?: NonceStore
    /** Accepts a state nothing burns. See {@link OAuth.Options.allowStateReplay}. */
    allowStateReplay?: boolean
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

  /** Records a state nonce once, answering false when it has already been seen. Must be atomic across
   *  concurrent callers, and honour `ttlMs` per key rather than assuming one global window.
   *
   *  `memoryDPoPNonceStore()` and `redisDPoPNonceStore()` satisfy this; give the Redis one its own
   *  `prefix` so oauth nonces and DPoP jtis do not share a keyspace. */
  export interface NonceStore {
    /** Records `nonce`; false when it was already seen inside `ttlMs`. */
    recordSeen(nonce: string, ttlMs: number): Promise<boolean>
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
    /** The client that talks to the provider. */
    client: OAuthClient
    /** The callback URL registered with the provider. */
    redirectUri: string
    /** Secret used to sign the oauth `state` parameter. */
    stateSigningSecret: string
    /** Binds a callback to the browser that began the flow. See {@link OAuth.StateCookie}. */
    stateCookie?: StateCookie
    /** Burns `StatePayload.nonce` at `complete`, so one signed state completes exactly once.
     *  SECURITY: without it a callback URL recovered from browser history, a `Referer` or a proxy log
     *  completes again for the rest of the state's ten minutes, from any browser still holding the
     *  binding cookie — which a failed completion leaves in place, since only the success path clears it. */
    nonceStore?: NonceStore
    /** Accepts a state nothing burns. Default false: the nonce is minted and signed either way, so an
     *  absent store reads as replay protection that is present and off. */
    allowStateReplay?: boolean
    /**
     * How the IdP returns the authorisation code. `'query'` is the default and the redirect every other
     * provider performs. `'form_post'` (OAuth 2.0 Form Post Response Mode) is what Apple requires as soon
     * as any scope is requested, and it changes two things at once, which is why it is one flag: the
     * authorize request carries `response_mode=form_post`, and the pre-auth cookie has to be
     * `SameSite=None` to survive a cross-site POST. Set by the provider module, not by the host.
     */
    responseMode?: 'query' | 'form_post'
    /** Extract a canonical profile from the token response, the userinfo endpoint or the callback itself. */
    fetchProfile: (
      tokens: { access_token: string; id_token?: string },
      client: OAuthClient,
      input: CompleteInput,
    ) => Promise<Profile>
    /** Map Profile -> consumer Profile shape on first sign-in; `null` refuses it. Unset refuses every first sign-in. */
    profileToIdentityProfile?: (p: Profile) => AppProfile | null
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

  /** An identity owning the profile's email with no link to this provider. `existingEmailVerified` is whether
   *  that identity proved the address; an unproven one may be a squatter's. */
  export interface FederationConflict {
    existingEmailVerified: boolean
    existingIdentityId: string
    profile: Profile
    providerId: string
  }

  /** Policy + hook shape for the federation conflict workflow. `'link-if-verified'` links only when both the
   *  provider and the existing identity have verified the address. */
  export type FederationPolicy =
    | 'reject'
    | 'link-if-verified'
    | ((ctx: FederationConflict) => Promise<'link' | 'reject'>)

  /** What starting an OAuth sign-in takes. */
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

  /** What the callback hands back to finish the sign-in. */
  export interface CompleteInput {
    /** Authorisation code returned by the provider. */
    code: string
    /** Opaque state value the library issued at begin. */
    state: string
    /** The callback request's `Cookie` header, verbatim.
     *  SECURITY: without it the signed state verifies from any browser, so an attacker completes their own
     *  flow, hands over the callback URL, and the victim signs in as the attacker. */
    cookieHeader?: string
    /** Apple's form_post `user` field, verbatim. It carries the name, and Apple sends it on the first
     *  authorization only, so a callback that drops it loses the name for good. */
    user?: string
  }

  /** Signed `state` payload, `<payload-base64url>.<sig-base64url>` under HMAC-SHA256 with the engine's signing
   *  secret. Signed, not secret: the IdP round-trips it in URLs. */
  export interface StatePayload {
    /** Random per flow, and what `Options.nonceStore` burns so one state completes once. */
    nonce: string
    /** Provider id; library refuses if it doesn't match the callback. */
    providerId: string
    /** Digest of the cookie `begin` set, which is also the PKCE verifier. Presenting the cookie proves the
     *  callback reached the browser that started the flow. */
    binding: string
    /** Optional return-to path on the app, as `begin` minted it. Round-tripped and length-capped, never
     *  read after that - see `BeginInput.returnTo`. */
    returnTo?: string
    /** Issued-at, in epoch ms. A state stamped more than ten minutes either side of now is refused. */
    iat: number
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

  /** Apple-specific options. No `clientSecret`: one is minted per request from the team, key and private key. */
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
