/**
 * Minimal OIDC OP. Implements:
 *
 *   GET  /authorize  (response_type=code + S256 PKCE)
 *   POST /token      (authorization_code + refresh_token grants)
 *   GET  /userinfo   (Bearer opaque access token)
 *   POST /introspect (RFC 7662, confidential clients only)
 *   POST /revoke     (RFC 7009)
 *
 * The host wires HTTP routing and presents login/consent UIs; this
 * module owns the state machine.
 */

import type { AuthEngine } from '../../core/auth'
import { getProfileString, isFiniteNumber, isProfileBooleanTrue } from '../../core/credential-utils'
import { authRandomToken, authSha256, authTimingSafeEqual } from '../../core/crypto'
import type { AuthIdentity } from '../../core/types/identity'
import {
  AuthMemoryAccessTokenStore,
  AuthMemoryCodeStore,
  AuthMemoryConsentStore,
  AuthMemoryRefreshTokenStore,
  MemoryClientStore,
} from './stores'
import type { AuthOidcOP } from './types'

export type { AuthOidcOP } from './types'
export {
  AuthMemoryAccessTokenStore,
  AuthMemoryCodeStore,
  AuthMemoryConsentStore,
  AuthMemoryRefreshTokenStore,
  MemoryClientStore,
}

interface IDeps<Profile> {
  auth: AuthEngine<Profile>
  clients: AuthOidcOP.IClientStore
  codes: AuthOidcOP.ICodeStore
  accessTokens: AuthOidcOP.IAccessTokenStore
  refreshTokens: AuthOidcOP.IRefreshTokenStore
  consents: AuthOidcOP.IConsentStore
  /** Signs an ID-token. Returns the encoded JWT string. */
  signIdToken: (payload: Record<string, unknown>) => Promise<string> | string
}

const REQUIRED_SCOPE = 'openid'
const DEFAULT_TTLS = {
  accessToken: 3600,
  refreshToken: 30 * 24 * 3600,
  code: 600,
  idToken: 3600,
}
const SCOPE_STRING_MAX = 4096
const SCOPE_TOKEN_MAX = 64

function parseScopeString(raw: unknown): string[] | { error: string } {
  if (raw === undefined || raw === null || raw === '') return []
  if (typeof raw !== 'string') return { error: 'scope must be a string' }
  if (raw.length > SCOPE_STRING_MAX) return { error: 'scope too long' }
  const tokens = raw.split(/\s+/).filter((s) => s.length > 0)
  if (tokens.length > SCOPE_TOKEN_MAX) return { error: 'too many scopes' }
  return tokens
}

/**
 * The OP. Wire it up with `authCreateOidcOP({ auth, signIdToken, ... })`
 * and route `authorize` / `token` / `userinfo` / `introspect` / `revoke`
 * from your HTTP layer.
 */
export class AuthOidcOpRoot<Profile = unknown> {
  readonly issuer: string
  readonly supportedScopes: string[]
  private deps: IDeps<Profile>
  private ttls = { ...DEFAULT_TTLS }
  private dcrConfig: AuthOidcOP.IDcrConfig

  constructor(cfg: AuthOidcOP.IConfig, deps: IDeps<Profile>, dcr?: AuthOidcOP.IDcrConfig) {
    this.dcrConfig = dcr ?? { enabled: false }
    if (!cfg.issuer) throw new Error('AuthOidcOP: issuer required')
    const parsed = parseIssuer(cfg.issuer, cfg.allowHttp ?? false)
    this.issuer = parsed
    const scopes = new Set(cfg.supportedScopes)
    scopes.add(REQUIRED_SCOPE)
    this.supportedScopes = [...scopes]
    this.deps = deps
    if (isFiniteNumber(cfg.accessTokenTtl)) this.ttls.accessToken = cfg.accessTokenTtl
    if (isFiniteNumber(cfg.refreshTokenTtl)) this.ttls.refreshToken = cfg.refreshTokenTtl
    if (isFiniteNumber(cfg.codeTtl)) this.ttls.code = cfg.codeTtl
    if (isFiniteNumber(cfg.idTokenTtl)) this.ttls.idToken = cfg.idTokenTtl
  }

  /**
   * Register a new client. Returns the plaintext client_secret (or null
   * for public clients). Plaintext is never persisted.
   */
  async registerClient(input: {
    client_id: string
    client_secret?: string
    redirect_uris: string[]
    grant_types?: AuthOidcOP.IGrantType[]
    response_types?: AuthOidcOP.IResponseType[]
    token_endpoint_auth_method?: AuthOidcOP.ITokenEndpointAuthMethod
    scope?: string[]
    client_name?: string
    client_uri?: string
    logo_uri?: string
  }): Promise<{ client_id: string; client_secret: string | null }> {
    if (!input.client_id) throw new Error('registerClient: client_id required')
    if (input.redirect_uris.length === 0) {
      throw new Error('registerClient: at least one redirect_uri required')
    }
    for (const uri of input.redirect_uris) assertValidRedirect(uri)
    const method = input.token_endpoint_auth_method ?? (input.client_secret ? 'client_secret_basic' : 'none')
    const secret = method === 'none' ? null : (input.client_secret ?? authRandomToken(32))
    const row: AuthOidcOP.IClient = {
      client_id: input.client_id,
      client_secret_hash: secret === null ? null : authSha256(secret),
      redirect_uris: [...input.redirect_uris],
      grant_types: input.grant_types ?? ['authorization_code', 'refresh_token'],
      response_types: input.response_types ?? ['code'],
      token_endpoint_auth_method: method,
      scope: input.scope ?? [REQUIRED_SCOPE, 'profile', 'email', 'offline_access'],
      ...(input.client_name !== undefined && { client_name: input.client_name }),
      ...(input.client_uri !== undefined && { client_uri: input.client_uri }),
      ...(input.logo_uri !== undefined && { logo_uri: input.logo_uri }),
      createdAt: Date.now(),
    }
    await this.deps.clients.insert(row)
    return { client_id: row.client_id, client_secret: secret }
  }

  /**
   * RFC 7591 dynamic client registration. Host wires this on
   * `POST /register` and returns the result body as application/json.
   *
   * When `dcrConfig.initialAccessToken` is set, the request MUST carry
   * `Authorization: Bearer <token>` (constant-time compared) or the
   * call returns `{ error: 'unauthorized' }`. When unset, registration
   * is open and SHOULD be put behind a private network.
   *
   * Discovery doc must advertise `registration_endpoint` for clients
   * to find this; emit that field by passing `registrationEndpoint`
   * to `buildOidcDiscovery`.
   */
  async register(
    req: AuthOidcOP.IDcrRequest,
    headers: Headers,
  ): Promise<{ status: 201; body: AuthOidcOP.IDcrResponse } | { status: number; body: AuthOidcOP.IDcrError }> {
    if (!this.dcrConfig.enabled) {
      return { status: 403, body: { error: 'unauthorized', error_description: 'dynamic registration disabled' } }
    }
    if (this.dcrConfig.initialAccessToken !== undefined) {
      const auth = headers.get('authorization')
      if (!auth?.toLowerCase().startsWith('bearer ')) {
        return { status: 401, body: { error: 'unauthorized', error_description: 'initial access token required' } }
      }
      const presented = auth.slice(7).trim()
      if (!authTimingSafeEqual(presented, this.dcrConfig.initialAccessToken)) {
        return { status: 401, body: { error: 'unauthorized', error_description: 'invalid initial access token' } }
      }
    }
    if (!Array.isArray(req.redirect_uris) || req.redirect_uris.length === 0) {
      return {
        status: 400,
        body: { error: 'invalid_redirect_uri', error_description: 'redirect_uris must be a non-empty array' },
      }
    }
    const maxUris = this.dcrConfig.maxRedirectUris ?? 20
    if (req.redirect_uris.length > maxUris) {
      return {
        status: 400,
        body: { error: 'invalid_redirect_uri', error_description: `redirect_uris exceeds ${maxUris}` },
      }
    }
    for (const uri of req.redirect_uris) {
      if (typeof uri !== 'string' || uri.length === 0 || uri.length > 2048) {
        return { status: 400, body: { error: 'invalid_redirect_uri' } }
      }
      try {
        assertValidRedirect(uri)
      } catch (err) {
        const description = err instanceof Error ? err.message : 'invalid redirect_uri'
        return { status: 400, body: { error: 'invalid_redirect_uri', error_description: description } }
      }
    }
    const grantTypes = filterGrantTypes(req.grant_types ?? ['authorization_code', 'refresh_token'])
    if (grantTypes.length === 0) {
      return {
        status: 400,
        body: { error: 'invalid_client_metadata', error_description: 'no supported grant_types in request' },
      }
    }
    const responseTypes = filterResponseTypes(req.response_types ?? ['code'])
    if (responseTypes.length === 0) {
      return {
        status: 400,
        body: { error: 'invalid_client_metadata', error_description: 'no supported response_types in request' },
      }
    }
    const tokenAuth = normalizeTokenAuth(req.token_endpoint_auth_method)
    if (tokenAuth === null) {
      return {
        status: 400,
        body: { error: 'invalid_client_metadata', error_description: 'unsupported token_endpoint_auth_method' },
      }
    }
    const parsedScope = parseScopeString((req.scope ?? 'openid').trim())
    if (!Array.isArray(parsedScope)) {
      return { status: 400, body: { error: 'invalid_client_metadata', error_description: parsedScope.error } }
    }
    const scopeArr = parsedScope
    if (!scopeArr.includes(REQUIRED_SCOPE)) scopeArr.unshift(REQUIRED_SCOPE)
    for (const s of scopeArr) {
      if (!this.supportedScopes.includes(s)) {
        return {
          status: 400,
          body: { error: 'invalid_client_metadata', error_description: `scope '${s}' not supported` },
        }
      }
    }
    if (req.client_name !== undefined && (typeof req.client_name !== 'string' || req.client_name.length > 200)) {
      return { status: 400, body: { error: 'invalid_client_metadata', error_description: 'client_name too long' } }
    }
    const clientId = `dcr-${authRandomToken(16)}`
    const { client_secret } = await this.registerClient({
      client_id: clientId,
      redirect_uris: req.redirect_uris,
      grant_types: grantTypes,
      response_types: responseTypes,
      token_endpoint_auth_method: tokenAuth,
      scope: scopeArr,
      ...(req.client_name !== undefined && { client_name: req.client_name }),
      ...(req.client_uri !== undefined && { client_uri: req.client_uri }),
      ...(req.logo_uri !== undefined && { logo_uri: req.logo_uri }),
    })
    const issuedAt = Math.floor(Date.now() / 1000)
    return {
      status: 201,
      body: {
        client_id: clientId,
        ...(client_secret !== null && { client_secret }),
        client_id_issued_at: issuedAt,
        client_secret_expires_at: 0,
        redirect_uris: req.redirect_uris,
        grant_types: grantTypes,
        response_types: responseTypes,
        token_endpoint_auth_method: tokenAuth,
        scope: scopeArr.join(' '),
        ...(req.client_name !== undefined && { client_name: req.client_name }),
        ...(req.client_uri !== undefined && { client_uri: req.client_uri }),
        ...(req.logo_uri !== undefined && { logo_uri: req.logo_uri }),
      },
    }
  }

  /**
   * Validate an /authorize request and decide what the host should do
   * next: 302 to login, prompt consent, or 302 to redirect_uri with a
   * fresh code.
   */
  async authorize(
    req: AuthOidcOP.IAuthorizeRequest,
    httpReq: { headers: Headers },
  ): Promise<AuthOidcOP.IAuthorizeResult> {
    if (!req.client_id || typeof req.client_id !== 'string') {
      return { kind: 'error', status: 400, body: { error: 'invalid_request', error_description: 'client_id required' } }
    }
    const client = await this.deps.clients.findById(req.client_id)
    if (!client) {
      return { kind: 'error', status: 400, body: { error: 'invalid_client', error_description: 'unknown client_id' } }
    }
    if (!req.redirect_uri || !client.redirect_uris.includes(req.redirect_uri)) {
      return {
        kind: 'error',
        status: 400,
        body: { error: 'invalid_request', error_description: 'redirect_uri mismatch' },
      }
    }
    // From here on we can redirect errors back to redirect_uri per OIDC.
    if (req.response_type !== 'code') {
      return {
        kind: 'error',
        status: 302,
        redirectUri: req.redirect_uri,
        body: { error: 'unsupported_response_type', state: req.state },
      }
    }
    if (!client.response_types.includes('code')) {
      return {
        kind: 'error',
        status: 302,
        redirectUri: req.redirect_uri,
        body: { error: 'unauthorized_client', state: req.state },
      }
    }
    const parsedScope = parseScopeString(req.scope)
    if (!Array.isArray(parsedScope)) {
      return {
        kind: 'error',
        status: 302,
        redirectUri: req.redirect_uri,
        body: { error: 'invalid_scope', error_description: parsedScope.error, state: req.state },
      }
    }
    const requested = parsedScope
    if (!requested.includes(REQUIRED_SCOPE)) {
      return {
        kind: 'error',
        status: 302,
        redirectUri: req.redirect_uri,
        body: { error: 'invalid_scope', error_description: 'openid scope required', state: req.state },
      }
    }
    for (const s of requested) {
      if (!this.supportedScopes.includes(s) || !client.scope.includes(s)) {
        return {
          kind: 'error',
          status: 302,
          redirectUri: req.redirect_uri,
          body: { error: 'invalid_scope', error_description: `scope '${s}' not allowed`, state: req.state },
        }
      }
    }
    // PKCE is mandatory for public clients; we require S256 across the board.
    if (req.code_challenge_method && req.code_challenge_method !== 'S256') {
      return {
        kind: 'error',
        status: 302,
        redirectUri: req.redirect_uri,
        body: { error: 'invalid_request', error_description: 'only S256 PKCE supported', state: req.state },
      }
    }
    if (client.token_endpoint_auth_method === 'none' && !req.code_challenge) {
      return {
        kind: 'error',
        status: 302,
        redirectUri: req.redirect_uri,
        body: { error: 'invalid_request', error_description: 'PKCE required for public clients', state: req.state },
      }
    }
    // Resolve session for the host's browser.
    const resolved = await this.deps.auth.resolveSession(httpReq)
    if (!resolved?.identity) {
      if (req.prompt === 'none') {
        return {
          kind: 'error',
          status: 302,
          redirectUri: req.redirect_uri,
          body: { error: 'login_required', state: req.state },
        }
      }
      return { kind: 'login_required', reason: req.prompt === 'login' ? 'prompt_login' : 'no_session' }
    }
    // Consent gate.
    const consent = await this.deps.consents.find(resolved.identity.id, client.client_id)
    const consentCoversRequest = consent !== null && requested.every((s) => consent.scope.includes(s))
    if (!consentCoversRequest || req.prompt === 'consent') {
      if (req.prompt === 'none') {
        return {
          kind: 'error',
          status: 302,
          redirectUri: req.redirect_uri,
          body: { error: 'consent_required', state: req.state },
        }
      }
      return { kind: 'consent_required', client, scope: requested, identity: resolved.identity }
    }
    // All gates passed; mint a code.
    return this.mintCodeAndRedirect({
      client,
      identity: resolved.identity,
      redirect_uri: req.redirect_uri,
      scope: requested,
      state: req.state,
      nonce: req.nonce,
      code_challenge: req.code_challenge,
      code_challenge_method: req.code_challenge_method,
      sid: resolved.session.id,
      tenant_id: resolved.session.tenantId ?? null,
    })
  }

  /**
   * Host calls this after the user clicks "Allow" on the consent UI.
   * Persists the consent record and mints the code.
   */
  async completeConsent(input: {
    client_id: string
    identity: AuthIdentity.IIdentity<Profile>
    redirect_uri: string
    scope: string[]
    state?: string
    nonce?: string
    code_challenge?: string
    code_challenge_method?: string
    sid: string
    tenant_id: string | null
  }): Promise<AuthOidcOP.IAuthorizeResult> {
    const client = await this.deps.clients.findById(input.client_id)
    if (!client?.redirect_uris.includes(input.redirect_uri)) {
      return { kind: 'error', status: 400, body: { error: 'invalid_request' } }
    }
    await this.deps.consents.upsert({
      identity_id: input.identity.id,
      client_id: input.client_id,
      scope: input.scope,
      grantedAt: Date.now(),
    })
    return this.mintCodeAndRedirect({
      client,
      identity: input.identity,
      redirect_uri: input.redirect_uri,
      scope: input.scope,
      state: input.state,
      nonce: input.nonce,
      code_challenge: input.code_challenge,
      code_challenge_method: input.code_challenge_method,
      sid: input.sid,
      tenant_id: input.tenant_id,
    })
  }

  private async mintCodeAndRedirect(input: {
    client: AuthOidcOP.IClient
    identity: AuthIdentity.IIdentity<Profile>
    redirect_uri: string
    scope: string[]
    state?: string
    nonce?: string
    code_challenge?: string
    code_challenge_method?: string
    sid: string
    tenant_id: string | null
  }): Promise<AuthOidcOP.IAuthorizeResult> {
    const code = authRandomToken(32)
    const now = Date.now()
    const challengeMethod: AuthOidcOP.ICodeChallengeMethod | null =
      input.code_challenge_method === 'S256' ? 'S256' : input.code_challenge ? 'S256' : null
    await this.deps.codes.insert({
      code,
      client_id: input.client.client_id,
      identity_id: input.identity.id,
      redirect_uri: input.redirect_uri,
      scope: input.scope,
      nonce: input.nonce ?? null,
      code_challenge: input.code_challenge ?? null,
      code_challenge_method: challengeMethod,
      tenant_id: input.tenant_id,
      sid: input.sid,
      exp: now + this.ttls.code * 1000,
    })
    const url = new URL(input.redirect_uri)
    url.searchParams.set('code', code)
    if (input.state) url.searchParams.set('state', input.state)
    return { kind: 'redirect', url: url.toString() }
  }

  /** Handle a POST /token request. */
  async token(
    req: AuthOidcOP.ITokenRequest,
    headers: Headers,
  ): Promise<AuthOidcOP.ITokenResponse | AuthOidcOP.IOAuthError> {
    const clientAuth = await this.authenticateClient(req, headers)
    if ('error' in clientAuth) return clientAuth
    const { client } = clientAuth
    switch (req.grant_type) {
      case 'authorization_code':
        return this.grantAuthorizationCode(req, client)
      case 'refresh_token':
        return this.grantRefreshToken(req, client)
      default:
        return { error: 'unsupported_grant_type' }
    }
  }

  private async grantAuthorizationCode(
    req: AuthOidcOP.ITokenRequest,
    client: AuthOidcOP.IClient,
  ): Promise<AuthOidcOP.ITokenResponse | AuthOidcOP.IOAuthError> {
    if (!client.grant_types.includes('authorization_code')) {
      return { error: 'unauthorized_client' }
    }
    if (!req.code || typeof req.code !== 'string') {
      return { error: 'invalid_request', error_description: 'code required' }
    }
    if (!req.redirect_uri) {
      return { error: 'invalid_request', error_description: 'redirect_uri required' }
    }
    const now = Date.now()
    const row = await this.deps.codes.consume(req.code, now)
    if (!row) return { error: 'invalid_grant', error_description: 'code unknown or expired' }
    if (row.client_id !== client.client_id) return { error: 'invalid_grant', error_description: 'code/client mismatch' }
    if (row.redirect_uri !== req.redirect_uri) {
      return { error: 'invalid_grant', error_description: 'redirect_uri mismatch' }
    }
    if (row.code_challenge) {
      if (!req.code_verifier) return { error: 'invalid_grant', error_description: 'code_verifier required' }
      if (!verifyPkceS256(req.code_verifier, row.code_challenge)) {
        return { error: 'invalid_grant', error_description: 'code_verifier mismatch' }
      }
    }
    return this.issueTokens({
      client,
      identity_id: row.identity_id,
      tenant_id: row.tenant_id,
      scope: row.scope,
      nonce: row.nonce,
      sid: row.sid,
    })
  }

  private async grantRefreshToken(
    req: AuthOidcOP.ITokenRequest,
    client: AuthOidcOP.IClient,
  ): Promise<AuthOidcOP.ITokenResponse | AuthOidcOP.IOAuthError> {
    if (!client.grant_types.includes('refresh_token')) {
      return { error: 'unauthorized_client' }
    }
    if (!req.refresh_token || typeof req.refresh_token !== 'string') {
      return { error: 'invalid_request', error_description: 'refresh_token required' }
    }
    const now = Date.now()
    const hash = authSha256(req.refresh_token)
    const existing = await this.deps.refreshTokens.findByHash(hash, now)
    if (existing && existing.consumedAt !== null) {
      // Reuse detected: nuke the whole family.
      await this.deps.refreshTokens.revokeFamily(existing.family_id)
      return { error: 'invalid_grant', error_description: 'refresh token reuse detected' }
    }
    const row = await this.deps.refreshTokens.consume(hash, now)
    if (!row) return { error: 'invalid_grant', error_description: 'refresh token unknown / expired' }
    if (row.client_id !== client.client_id) return { error: 'invalid_grant' }
    let scope = row.scope
    if (req.scope) {
      const parsedScope = parseScopeString(req.scope)
      if (!Array.isArray(parsedScope)) return { error: 'invalid_scope', error_description: parsedScope.error }
      for (const s of parsedScope) {
        if (!row.scope.includes(s)) return { error: 'invalid_scope', error_description: `scope '${s}' not original` }
      }
      scope = parsedScope
    }
    return this.issueTokens({
      client,
      identity_id: row.identity_id,
      tenant_id: row.tenant_id,
      scope,
      nonce: null,
      sid: '',
      family_id: row.family_id,
    })
  }

  private async issueTokens(input: {
    client: AuthOidcOP.IClient
    identity_id: string
    tenant_id: string | null
    scope: string[]
    nonce: string | null
    sid: string
    family_id?: string
  }): Promise<AuthOidcOP.ITokenResponse> {
    const now = Math.floor(Date.now() / 1000)
    const accessTokenPlain = authRandomToken(48)
    const refreshTokenPlain = input.scope.includes('offline_access') ? authRandomToken(48) : null
    await this.deps.accessTokens.insert({
      token_hash: authSha256(accessTokenPlain),
      client_id: input.client.client_id,
      identity_id: input.identity_id,
      scope: input.scope,
      tenant_id: input.tenant_id,
      exp: (now + this.ttls.accessToken) * 1000,
    })
    let refreshOut: string | undefined
    if (refreshTokenPlain) {
      const family = input.family_id ?? authRandomToken(16)
      await this.deps.refreshTokens.insert({
        token_hash: authSha256(refreshTokenPlain),
        family_id: family,
        client_id: input.client.client_id,
        identity_id: input.identity_id,
        scope: input.scope,
        tenant_id: input.tenant_id,
        exp: (now + this.ttls.refreshToken) * 1000,
        consumedAt: null,
      })
      refreshOut = refreshTokenPlain
    }
    const idTokenPayload: Record<string, unknown> = {
      iss: this.issuer,
      sub: input.identity_id,
      aud: input.client.client_id,
      iat: now,
      exp: now + this.ttls.idToken,
      ...(input.nonce !== null && { nonce: input.nonce }),
      ...(input.sid !== '' && { sid: input.sid }),
      ...(input.tenant_id !== null && { tid: input.tenant_id }),
    }
    const idToken = await this.deps.signIdToken(idTokenPayload)
    return {
      access_token: accessTokenPlain,
      token_type: 'Bearer',
      expires_in: this.ttls.accessToken,
      scope: input.scope.join(' '),
      id_token: idToken,
      ...(refreshOut !== undefined && { refresh_token: refreshOut }),
    }
  }

  /** Handle /userinfo. Verifies bearer access token and returns scope-gated claims. */
  async userinfo(
    headers: Headers,
    ctx: { tenantId?: string } = {},
  ): Promise<AuthOidcOP.IUserinfoClaims | AuthOidcOP.IOAuthError> {
    const auth = headers.get('authorization')
    if (!auth?.toLowerCase().startsWith('bearer ')) {
      return { error: 'invalid_token', error_description: 'Bearer token required' }
    }
    const token = auth.slice(7).trim()
    if (!token) return { error: 'invalid_token' }
    const row = await this.deps.accessTokens.findByHash(authSha256(token), Date.now())
    if (!row) return { error: 'invalid_token', error_description: 'token unknown / expired' }
    if (ctx.tenantId !== undefined && row.tenant_id !== ctx.tenantId) {
      return { error: 'invalid_token', error_description: 'cross-tenant token' }
    }
    const identity = await this.deps.auth.identities.getById(row.identity_id, {})
    if (!identity) return { error: 'invalid_token', error_description: 'subject not found' }
    const claims: AuthOidcOP.IUserinfoClaims = { sub: identity.id }
    if (row.scope.includes('profile')) {
      const name = getProfileString(identity.profile, 'name')
      const username = getProfileString(identity.profile, 'username') ?? getProfileString(identity.profile, 'login')
      if (name !== undefined) claims.name = name
      if (username !== undefined) claims.preferred_username = username
    }
    if (row.scope.includes('email')) {
      const email = getProfileString(identity.profile, 'email')
      if (email !== undefined) {
        claims.email = email
        claims.email_verified = isProfileBooleanTrue(identity.profile, 'email_verified')
      }
    }
    return claims
  }

  /**
   * RFC 7662 introspection. Confidential clients only.
   * Returns `{ active: false }` for unknown / expired tokens.
   */
  async introspect(
    req: { token: string; token_type_hint?: 'access_token' | 'refresh_token' },
    headers: Headers,
  ): Promise<{ active: boolean; [k: string]: unknown }> {
    const clientAuth = await this.authenticateClient({ grant_type: '' }, headers)
    if ('error' in clientAuth) return { active: false }
    if (clientAuth.client.token_endpoint_auth_method === 'none') return { active: false }
    const now = Date.now()
    if (req.token_type_hint !== 'refresh_token') {
      const at = await this.deps.accessTokens.findByHash(authSha256(req.token), now)
      if (at) {
        return {
          active: true,
          client_id: at.client_id,
          scope: at.scope.join(' '),
          sub: at.identity_id,
          exp: Math.floor(at.exp / 1000),
          token_type: 'Bearer',
        }
      }
    }
    if (req.token_type_hint !== 'access_token') {
      const rt = await this.deps.refreshTokens.findByHash(authSha256(req.token), now)
      if (rt && rt.consumedAt === null) {
        return {
          active: true,
          client_id: rt.client_id,
          scope: rt.scope.join(' '),
          sub: rt.identity_id,
          exp: Math.floor(rt.exp / 1000),
          token_type: 'refresh_token',
        }
      }
    }
    return { active: false }
  }

  /** RFC 7009 token revocation. */
  async revoke(
    req: { token: string; token_type_hint?: 'access_token' | 'refresh_token' },
    headers: Headers,
  ): Promise<void> {
    const clientAuth = await this.authenticateClient({ grant_type: '' }, headers)
    if ('error' in clientAuth) return
    const hash = authSha256(req.token)
    if (req.token_type_hint !== 'refresh_token') {
      await this.deps.accessTokens.revokeByHash(hash)
    }
    if (req.token_type_hint !== 'access_token') {
      const rt = await this.deps.refreshTokens.findByHash(hash, Date.now())
      if (rt) await this.deps.refreshTokens.revokeFamily(rt.family_id)
    }
  }

  private async authenticateClient(
    req: AuthOidcOP.ITokenRequest,
    headers: Headers,
  ): Promise<{ client: AuthOidcOP.IClient } | AuthOidcOP.IOAuthError> {
    const basic = parseBasicAuth(headers.get('authorization'))
    const clientIdFromBasic = basic?.user
    const clientSecretFromBasic = basic?.pass
    const clientId = clientIdFromBasic ?? req.client_id
    if (!clientId) return { error: 'invalid_client', error_description: 'client_id required' }
    const client = await this.deps.clients.findById(clientId)
    if (!client) return { error: 'invalid_client' }
    switch (client.token_endpoint_auth_method) {
      case 'none':
        // Public clients prove themselves via PKCE; no secret to check.
        return { client }
      case 'client_secret_basic':
        if (!clientSecretFromBasic) return { error: 'invalid_client', error_description: 'Basic auth required' }
        if (
          !client.client_secret_hash ||
          !authTimingSafeEqual(authSha256(clientSecretFromBasic), client.client_secret_hash)
        ) {
          return { error: 'invalid_client' }
        }
        return { client }
      case 'client_secret_post':
        if (!req.client_secret) return { error: 'invalid_client', error_description: 'client_secret required in body' }
        if (
          !client.client_secret_hash ||
          !authTimingSafeEqual(authSha256(req.client_secret), client.client_secret_hash)
        ) {
          return { error: 'invalid_client' }
        }
        return { client }
      default:
        return { error: 'invalid_client' }
    }
  }
}

/** Convenience factory with sensible memory-store defaults. */
export function authCreateOidcOP<Profile = unknown>(args: {
  auth: AuthEngine<Profile>
  config: AuthOidcOP.IConfig
  signIdToken: (payload: Record<string, unknown>) => Promise<string> | string
  dcr?: AuthOidcOP.IDcrConfig
  stores?: {
    clients?: AuthOidcOP.IClientStore
    codes?: AuthOidcOP.ICodeStore
    accessTokens?: AuthOidcOP.IAccessTokenStore
    refreshTokens?: AuthOidcOP.IRefreshTokenStore
    consents?: AuthOidcOP.IConsentStore
  }
}): AuthOidcOpRoot<Profile> {
  return new AuthOidcOpRoot<Profile>(
    args.config,
    {
      auth: args.auth,
      clients: args.stores?.clients ?? new MemoryClientStore(),
      codes: args.stores?.codes ?? new AuthMemoryCodeStore(),
      accessTokens: args.stores?.accessTokens ?? new AuthMemoryAccessTokenStore(),
      refreshTokens: args.stores?.refreshTokens ?? new AuthMemoryRefreshTokenStore(),
      consents: args.stores?.consents ?? new AuthMemoryConsentStore(),
      signIdToken: args.signIdToken,
    },
    args.dcr,
  )
}

function parseIssuer(input: string, allowHttp: boolean): string {
  let parsed: URL
  try {
    parsed = new URL(input)
  } catch {
    throw new Error(`AuthOidcOP: issuer '${input}' is not a valid URL`)
  }
  if (parsed.protocol !== 'https:' && !allowHttp) {
    throw new Error(`AuthOidcOP: issuer must use HTTPS (${parsed.protocol}); pass allowHttp: true for dev only`)
  }
  return `${parsed.origin}${parsed.pathname.replace(/\/+$/, '')}`
}

function assertValidRedirect(uri: string): void {
  let url: URL
  try {
    url = new URL(uri)
  } catch {
    throw new Error(`registerClient: redirect_uri '${uri}' is not a valid absolute URL`)
  }
  if (url.hash !== '') throw new Error(`registerClient: redirect_uri must not include a fragment`)
  if (url.protocol === 'http:' && !isLoopbackHost(url.hostname)) {
    throw new Error(`registerClient: non-loopback http redirect_uri rejected: ${uri}`)
  }
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]'
}

function verifyPkceS256(verifier: string, expectedChallenge: string): boolean {
  if (verifier.length < 43 || verifier.length > 128) return false
  // RFC 7636: base64url(SHA256(verifier))
  const computed = base64urlSha256(verifier)
  return authTimingSafeEqual(computed, expectedChallenge)
}

function base64urlSha256(input: string): string {
  // node:crypto via the same path the rest of the package uses.
  // sha256() returns hex; convert to base64url.
  const hex = authSha256(input)
  const bytes = Buffer.from(hex, 'hex')
  return bytes.toString('base64url')
}

function filterGrantTypes(input: string[]): AuthOidcOP.IGrantType[] {
  const allowed: AuthOidcOP.IGrantType[] = []
  for (const g of input) {
    if (g === 'authorization_code' || g === 'refresh_token') {
      if (!allowed.includes(g)) allowed.push(g)
    }
  }
  return allowed
}

function filterResponseTypes(input: string[]): AuthOidcOP.IResponseType[] {
  const allowed: AuthOidcOP.IResponseType[] = []
  for (const r of input) {
    if (r === 'code' && !allowed.includes(r)) allowed.push(r)
  }
  return allowed
}

function normalizeTokenAuth(input: string | undefined): AuthOidcOP.ITokenEndpointAuthMethod | null {
  if (input === undefined) return 'client_secret_basic'
  if (input === 'client_secret_basic' || input === 'client_secret_post' || input === 'none') return input
  return null
}

function parseBasicAuth(header: string | null): { user: string; pass: string } | null {
  if (!header) return null
  const trimmed = header.trim()
  if (!trimmed.toLowerCase().startsWith('basic ')) return null
  const b64 = trimmed.slice(6).trim()
  if (!b64) return null
  let decoded: string
  try {
    decoded = Buffer.from(b64, 'base64').toString('utf8')
  } catch {
    return null
  }
  const idx = decoded.indexOf(':')
  if (idx < 0) return null
  return { user: decoded.slice(0, idx), pass: decoded.slice(idx + 1) }
}
