import { AuthErrorObject } from '../../../core/errors'

export namespace OAuthClient {
  /**
   * OIDC / OAuth2 endpoints. Supplied directly (Google, GitHub,
   * static well-known providers) or resolved at runtime via discovery
   * for generic OIDC issuers.
   */
  export interface IEndpoints {
    authorizationEndpoint: string
    tokenEndpoint: string
    /** OIDC userinfo (optional - providers often expose a profile endpoint instead). */
    userinfoEndpoint?: string
    /** OIDC revocation (optional). */
    revocationEndpoint?: string
  }

  /** Config knobs for the OAuth client. */
  export interface IOptions {
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
    endpoints: IEndpoints | (() => Promise<IEndpoints>)
    /** OAuth2 scopes the provider should request. */
    scopes: string[]
    /** Override the fetch impl (test stubs). */
    fetch?: typeof globalThis.fetch
  }

  /** Standard OAuth2 token-endpoint response. */
  export interface ITokenResponse {
    access_token: string
    token_type: string
    expires_in?: number
    refresh_token?: string
    id_token?: string
    scope?: string
  }
}

export class OAuthClient {
  private _endpoints: OAuthClient.IEndpoints | null = null

  constructor(private readonly _opts: OAuthClient.IOptions) {}

  /**
   * Resolve the per-call client_secret. Dynamic generator wins when
   * supplied (Sign in with Apple); otherwise the static value is used.
   * Returns undefined when neither is configured (PKCE public clients).
   */
  private async _resolveSecret(): Promise<string | undefined> {
    if (this._opts.dynamicClientSecret) {
      const value = await this._opts.dynamicClientSecret()
      // Reject non-string returns from the operator's dynamic-secret callback;
      // a falsy/object/number value would otherwise propagate into the URLSearchParams
      // body as the literal string and corrupt the token exchange.
      if (typeof value !== 'string') return undefined
      return value.length === 0 ? undefined : value
    }
    return this._opts.clientSecret || undefined
  }

  private async _resolveEndpoints(): Promise<OAuthClient.IEndpoints> {
    if (this._endpoints) return this._endpoints
    const e = typeof this._opts.endpoints === 'function' ? await this._opts.endpoints() : this._opts.endpoints
    // Validate endpoint URLs at resolution time. A buggy/typo'd dynamic
    // endpoints callback that returns a `javascript:`/`file:` URL would
    // otherwise reach fetch() and either fail unhelpfully or fire on an
    // unintended scheme.
    if (typeof e?.authorizationEndpoint !== 'string' || !isHttpUrl(e.authorizationEndpoint)) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', { detail: 'oauth: authorizationEndpoint must be an http(s) URL' })
    }
    if (typeof e.tokenEndpoint !== 'string' || !isHttpUrl(e.tokenEndpoint)) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', { detail: 'oauth: tokenEndpoint must be an http(s) URL' })
    }
    if (
      e.userinfoEndpoint !== undefined &&
      (typeof e.userinfoEndpoint !== 'string' || !isHttpUrl(e.userinfoEndpoint))
    ) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', { detail: 'oauth: userinfoEndpoint must be an http(s) URL' })
    }
    if (
      e.revocationEndpoint !== undefined &&
      (typeof e.revocationEndpoint !== 'string' || !isHttpUrl(e.revocationEndpoint))
    ) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', { detail: 'oauth: revocationEndpoint must be an http(s) URL' })
    }
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
  async exchangeCode(opts: {
    code: string
    redirectUri: string
    codeVerifier: string
  }): Promise<OAuthClient.ITokenResponse> {
    const e = await this._resolveEndpoints()
    const fetchImpl = this._opts.fetch ?? globalThis.fetch
    const secret = await this._resolveSecret()
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: opts.code,
      redirect_uri: opts.redirectUri,
      client_id: this._opts.clientId,
      code_verifier: opts.codeVerifier,
      ...(secret !== undefined && { client_secret: secret }),
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
    // Strict parse; non-numeric `expires_in` would propagate NaN past expiry.
    const tokens = parseTokenResponse(await readJsonSafe(res))
    if (!tokens) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId: 'oauth',
        detail: 'token endpoint returned malformed response',
      })
    }
    return tokens
  }

  /** Refresh-token rotation; throws on any non-2xx. */
  async refresh(refreshToken: string): Promise<OAuthClient.ITokenResponse> {
    const e = await this._resolveEndpoints()
    const fetchImpl = this._opts.fetch ?? globalThis.fetch
    const secret = await this._resolveSecret()
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: this._opts.clientId,
      ...(secret !== undefined && { client_secret: secret }),
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
    const tokens = parseTokenResponse(await readJsonSafe(res))
    if (!tokens) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId: 'oauth',
        detail: 'refresh endpoint returned malformed response',
      })
    }
    return tokens
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
    // userinfo bodies are IdP-controlled. Require an object shape
    // before handing the body back to caller-supplied `fetchProfile`.
    const json = await readJsonSafe(res)
    if (!isPlainObject(json)) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId: 'oauth',
        detail: 'userinfo returned non-object body',
      })
    }
    return json
  }
}

function isHttpUrl(value: string): boolean {
  try {
    const u = new URL(value)
    return u.protocol === 'https:' || u.protocol === 'http:'
  } catch {
    return false
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

async function readJsonSafe(res: Response): Promise<unknown> {
  // Stream + cap so a hostile IdP that streams a multi-GB body cannot OOM us
  // before we ever reach JSON.parse. Real OAuth token / userinfo bodies are
  // <10KB; 64KB is generous.
  const MAX_BYTES = 64 * 1024
  const reader = res.body?.getReader()
  if (!reader) {
    try {
      return await res.json()
    } catch {
      return null
    }
  }
  const decoder = new TextDecoder()
  let text = ''
  let bytes = 0
  try {
    while (bytes < MAX_BYTES) {
      const { value, done } = await reader.read()
      if (done) break
      bytes += value.byteLength
      text += decoder.decode(value, { stream: true })
      if (bytes >= MAX_BYTES) return null
    }
    text += decoder.decode()
  } catch {
    return null
  } finally {
    void reader.cancel().catch(() => {})
  }
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

/** Validator for OAuth2 token-endpoint responses (RFC 6749 section 5.1). */
function parseTokenResponse(raw: unknown): OAuthClient.ITokenResponse | null {
  if (!isPlainObject(raw)) return null
  const { access_token, token_type, expires_in, refresh_token, id_token, scope } = raw
  if (typeof access_token !== 'string' || access_token.length === 0) return null
  if (typeof token_type !== 'string' || token_type.length === 0) return null
  if (expires_in !== undefined && (typeof expires_in !== 'number' || !Number.isFinite(expires_in))) return null
  if (refresh_token !== undefined && typeof refresh_token !== 'string') return null
  if (id_token !== undefined && typeof id_token !== 'string') return null
  if (scope !== undefined && typeof scope !== 'string') return null
  const r: OAuthClient.ITokenResponse = { access_token, token_type }
  if (expires_in !== undefined) r.expires_in = expires_in
  if (refresh_token !== undefined) r.refresh_token = refresh_token
  if (id_token !== undefined) r.id_token = id_token
  if (scope !== undefined) r.scope = scope
  return r
}
