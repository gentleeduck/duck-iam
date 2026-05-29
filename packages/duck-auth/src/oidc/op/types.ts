/**
 * Types for the minimal OIDC OP.
 *
 * Scope: authorization_code grant + refresh_token grant + S256 PKCE,
 * /userinfo with bearer-opaque access tokens, scope-gated claims.
 *
 * Out of scope: implicit / hybrid flows, JAR/PAR, DCR, request URI,
 * pairwise subject identifiers, claims request parameter, ACR/AMR
 * claim mapping, distributed claims, RP-initiated logout (separate).
 */

import type { Identity } from '../../core/types/identity'

export namespace OidcOP {
  export type IGrantType = 'authorization_code' | 'refresh_token'
  export type IResponseType = 'code'
  export type ITokenEndpointAuthMethod = 'client_secret_basic' | 'client_secret_post' | 'none'
  export type ICodeChallengeMethod = 'S256' | 'plain'
  export type IPrompt = 'none' | 'login' | 'consent' | 'select_account'

  /** A registered OIDC client. */
  export interface IClient {
    client_id: string
    /** Hashed (sha256) secret. `null` for public clients. */
    client_secret_hash: string | null
    redirect_uris: string[]
    grant_types: IGrantType[]
    response_types: IResponseType[]
    token_endpoint_auth_method: ITokenEndpointAuthMethod
    /** Scopes the client is allowed to ask for. Subset of OP-supported. */
    scope: string[]
    /** Display name for consent screen. */
    client_name?: string
    /** Public homepage / logo for consent screen. */
    client_uri?: string
    logo_uri?: string
    /** Created-at, ms epoch. */
    createdAt: number
  }

  /** A pending authorization code. TTL ~10 min. */
  export interface ICode {
    code: string
    client_id: string
    identity_id: string
    redirect_uri: string
    scope: string[]
    nonce: string | null
    code_challenge: string | null
    code_challenge_method: ICodeChallengeMethod | null
    /** Tenant binding for cross-tenant guard. */
    tenant_id: string | null
    /** Session id used to mint this code; surfaced into id_token sid claim. */
    sid: string
    /** Expiry, ms epoch. */
    exp: number
  }

  /** An issued opaque access token. */
  export interface IAccessToken {
    /** Hashed token (sha256). Plaintext is only ever returned at issue time. */
    token_hash: string
    client_id: string
    identity_id: string
    scope: string[]
    tenant_id: string | null
    exp: number
  }

  /** An issued refresh token. Rotated on use; reuse triggers family revoke. */
  export interface IRefreshToken {
    token_hash: string
    family_id: string
    client_id: string
    identity_id: string
    scope: string[]
    tenant_id: string | null
    exp: number
    /** Set when this token has been used; reuse after this is set = reuse attack. */
    consumedAt: number | null
  }

  /** Per (subject, client_id) granted scopes. */
  export interface IConsent {
    identity_id: string
    client_id: string
    scope: string[]
    grantedAt: number
  }

  export interface IClientStore {
    findById(client_id: string): Promise<IClient | null>
    insert(c: IClient): Promise<void>
  }

  export interface ICodeStore {
    insert(c: ICode): Promise<void>
    /** Consume = atomic find-and-delete. Returns null if missing or expired. */
    consume(code: string, now: number): Promise<ICode | null>
  }

  export interface IAccessTokenStore {
    insert(t: IAccessToken): Promise<void>
    findByHash(hash: string, now: number): Promise<IAccessToken | null>
    revokeByHash(hash: string): Promise<void>
  }

  export interface IRefreshTokenStore {
    insert(t: IRefreshToken): Promise<void>
    findByHash(hash: string, now: number): Promise<IRefreshToken | null>
    /** Mark as consumed. Returns the row or null if already consumed / missing. */
    consume(hash: string, now: number): Promise<IRefreshToken | null>
    /** Revoke every refresh token in this family (reuse-attack defense). */
    revokeFamily(family_id: string): Promise<void>
  }

  export interface IConsentStore {
    find(identity_id: string, client_id: string): Promise<IConsent | null>
    upsert(c: IConsent): Promise<void>
  }

  /** Configuration for the OP. */
  export interface IConfig {
    /** Issuer URL. Must match the discovery doc. */
    issuer: string
    /** Supported scopes. Always includes `openid`. */
    supportedScopes: string[]
    /** Default access-token TTL in seconds. Default 3600. */
    accessTokenTtl?: number
    /** Default refresh-token TTL in seconds. Default 30 days. */
    refreshTokenTtl?: number
    /** Auth-code TTL in seconds. Default 600. */
    codeTtl?: number
    /** ID-token TTL in seconds. Default 3600. */
    idTokenTtl?: number
    /** Allow http issuer for dev. Production OPs must be https. */
    allowHttp?: boolean
  }

  /** OAuth2-style standard error codes per RFC 6749 §5.2 / OIDC core §3.1.2.6. */
  export type IErrorCode =
    | 'invalid_request'
    | 'invalid_client'
    | 'invalid_grant'
    | 'unauthorized_client'
    | 'unsupported_grant_type'
    | 'unsupported_response_type'
    | 'invalid_scope'
    | 'access_denied'
    | 'server_error'
    | 'login_required'
    | 'consent_required'
    | 'interaction_required'
    | 'invalid_token'
    | 'insufficient_scope'

  export interface IOAuthError {
    error: IErrorCode
    error_description?: string
    /** OAuth state echo for redirect-bearing errors. */
    state?: string
  }

  /** /authorize request shape, post URL parse + validation. */
  export interface IAuthorizeRequest {
    client_id: string
    redirect_uri: string
    response_type: string
    scope: string
    state?: string
    nonce?: string
    code_challenge?: string
    code_challenge_method?: string
    prompt?: string
  }

  /** /authorize result the host app routes on. */
  export type IAuthorizeResult =
    | { kind: 'redirect'; url: string }
    | { kind: 'login_required'; reason: 'no_session' | 'prompt_login' | 'max_age_exceeded' }
    | { kind: 'consent_required'; client: IClient; scope: string[]; identity: Identity.IIdentity<unknown> }
    | { kind: 'error'; status: number; body: IOAuthError; redirectUri?: string }

  /** /token request shape, post body parse. */
  export interface ITokenRequest {
    grant_type: string
    code?: string
    redirect_uri?: string
    client_id?: string
    client_secret?: string
    refresh_token?: string
    code_verifier?: string
    /** Subset of original scope when refreshing. */
    scope?: string
  }

  /** /token success body. */
  export interface ITokenResponse {
    access_token: string
    token_type: 'Bearer'
    expires_in: number
    refresh_token?: string
    id_token?: string
    scope: string
  }

  /** /userinfo claim payload. Shape varies with granted scopes. */
  export interface IUserinfoClaims {
    sub: string
    /** Present when `profile` scope granted. */
    name?: string
    preferred_username?: string
    /** Present when `email` scope granted. */
    email?: string
    email_verified?: boolean
    [k: string]: unknown
  }

  /** RFC 7591 dynamic client registration request body. */
  export interface IDcrRequest {
    redirect_uris: string[]
    client_name?: string
    client_uri?: string
    logo_uri?: string
    contacts?: string[]
    tos_uri?: string
    policy_uri?: string
    scope?: string
    grant_types?: string[]
    response_types?: string[]
    token_endpoint_auth_method?: string
  }

  /** RFC 7591 success response. */
  export interface IDcrResponse {
    client_id: string
    client_secret?: string
    client_id_issued_at: number
    client_secret_expires_at: number
    redirect_uris: string[]
    grant_types: string[]
    response_types: string[]
    token_endpoint_auth_method: string
    scope: string
    client_name?: string
    client_uri?: string
    logo_uri?: string
  }

  /** RFC 7591 standardized error response. */
  export interface IDcrError {
    error: 'invalid_client_metadata' | 'invalid_redirect_uri' | 'unauthorized'
    error_description?: string
  }

  /** DCR controller config. */
  export interface IDcrConfig {
    /** Master switch. Default false. */
    enabled: boolean
    /**
     * Required bearer token for /register. When set, callers must
     * present `Authorization: Bearer <token>` matching this value.
     * When unset, /register is OPEN registration (use behind a VPN /
     * private network only).
     */
    initialAccessToken?: string
    /** Cap how many redirect_uris a DCR client may register. Default 20. */
    maxRedirectUris?: number
  }
}
