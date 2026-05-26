import { AuthErrorObject } from '../../../core/errors'

/**
 * OIDC / OAuth2 endpoints. Either supplied directly (Google, GitHub,
 * static well-known providers) or resolved at runtime via discovery for
 * generic OIDC issuers (`well-known/openid-configuration`).
 */
export interface OAuthEndpoints {
  authorizationEndpoint: string
  tokenEndpoint: string
  /** OIDC userinfo (optional — providers often expose a profile endpoint instead). */
  userinfoEndpoint?: string
  /** OIDC revocation (optional). */
  revocationEndpoint?: string
}

export interface OAuthClientOptions {
  clientId: string
  clientSecret?: string
  /** Endpoints; can be promised when discovering at boot. */
  endpoints: OAuthEndpoints | (() => Promise<OAuthEndpoints>)
  /** OAuth2 scopes the provider should request. */
  scopes: string[]
  /** Override the fetch impl (test stubs). */
  fetch?: typeof globalThis.fetch
}

export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in?: number
  refresh_token?: string
  id_token?: string
  scope?: string
}

export class OAuthClient {
  private _endpoints: OAuthEndpoints | null = null

  constructor(private readonly _opts: OAuthClientOptions) {}

  private async _resolveEndpoints(): Promise<OAuthEndpoints> {
    if (this._endpoints) return this._endpoints
    const e = typeof this._opts.endpoints === 'function' ? await this._opts.endpoints() : this._opts.endpoints
    this._endpoints = e
    return e
  }

  /** Build the authorization redirect URL with PKCE + state. */
  async buildAuthorizeUrl(opts: {
    redirectUri: string
    state: string
    codeChallenge: string
    nonce?: string
    extraParams?: Record<string, string>
  }): Promise<string> {
    const e = await this._resolveEndpoints()
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this._opts.clientId,
      redirect_uri: opts.redirectUri,
      scope: this._opts.scopes.join(' '),
      state: opts.state,
      code_challenge: opts.codeChallenge,
      code_challenge_method: 'S256',
      ...(opts.nonce !== undefined && { nonce: opts.nonce }),
      ...(opts.extraParams ?? {}),
    })
    return `${e.authorizationEndpoint}?${params.toString()}`
  }

  /** Exchange an authorisation code for tokens. PKCE verifier required. */
  async exchangeCode(opts: { code: string; redirectUri: string; codeVerifier: string }): Promise<TokenResponse> {
    const e = await this._resolveEndpoints()
    const fetchImpl = this._opts.fetch ?? globalThis.fetch
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: opts.code,
      redirect_uri: opts.redirectUri,
      client_id: this._opts.clientId,
      code_verifier: opts.codeVerifier,
      ...(this._opts.clientSecret !== undefined && { client_secret: this._opts.clientSecret }),
    })
    const res = await fetchImpl(e.tokenEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    })
    if (!res.ok) {
      const text = await res.text().catch(() => '')
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId: 'oauth',
        detail: `token endpoint returned ${res.status}: ${text.slice(0, 200)}`,
      })
    }
    return (await res.json()) as TokenResponse
  }

  /** Refresh-token rotation; throws on any non-2xx. Reuse detection is at the facet level. */
  async refresh(refreshToken: string): Promise<TokenResponse> {
    const e = await this._resolveEndpoints()
    const fetchImpl = this._opts.fetch ?? globalThis.fetch
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: this._opts.clientId,
      ...(this._opts.clientSecret !== undefined && { client_secret: this._opts.clientSecret }),
    })
    const res = await fetchImpl(e.tokenEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    })
    if (!res.ok) {
      const text = await res.text().catch(() => '')
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId: 'oauth',
        detail: `refresh failed ${res.status}: ${text.slice(0, 200)}`,
      })
    }
    return (await res.json()) as TokenResponse
  }

  /** Fetch the OIDC userinfo profile (when the provider exposes one). */
  async userinfo(accessToken: string): Promise<Record<string, unknown>> {
    const e = await this._resolveEndpoints()
    if (!e.userinfoEndpoint) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'oauth: userinfoEndpoint not configured for this provider',
      })
    }
    const fetchImpl = this._opts.fetch ?? globalThis.fetch
    const res = await fetchImpl(e.userinfoEndpoint, {
      headers: { authorization: `Bearer ${accessToken}` },
    })
    if (!res.ok) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId: 'oauth',
        detail: `userinfo failed ${res.status}`,
      })
    }
    return (await res.json()) as Record<string, unknown>
  }
}
