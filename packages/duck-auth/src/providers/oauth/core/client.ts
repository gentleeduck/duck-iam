import { AuthError } from '~/core/errors'
import type { OAuth } from './oauth.types'

export class OAuthClient {
  private _endpoints: OAuth.Endpoints | null = null

  constructor(private readonly _opts: OAuth.ClientOptions) {}

  /** The dynamic generator wins when supplied (Sign in with Apple); undefined means a PKCE public client. */
  private async _resolveSecret(): Promise<string | undefined> {
    if (this._opts.dynamicClientSecret) {
      const value = await this._opts.dynamicClientSecret()
      // A falsy/object/number return would otherwise stringify into the URLSearchParams body and
      // corrupt the token exchange.
      if (typeof value !== 'string') return undefined
      return value.length === 0 ? undefined : value
    }
    return this._opts.clientSecret || undefined
  }

  private async _resolveEndpoints(): Promise<OAuth.Endpoints> {
    if (this._endpoints) return this._endpoints
    const e = typeof this._opts.endpoints === 'function' ? await this._opts.endpoints() : this._opts.endpoints
    // SECURITY: a dynamic endpoints callback that answers a `javascript:` or `file:` URL would otherwise
    // reach fetch() on an unintended scheme.
    if (typeof e?.authorizationEndpoint !== 'string' || !isHttpUrl(e.authorizationEndpoint)) {
      throw new AuthError('AUTH_MISCONFIGURED', { detail: 'oauth: authorizationEndpoint must be an http(s) URL' })
    }
    if (typeof e.tokenEndpoint !== 'string' || !isHttpUrl(e.tokenEndpoint)) {
      throw new AuthError('AUTH_MISCONFIGURED', { detail: 'oauth: tokenEndpoint must be an http(s) URL' })
    }
    if (
      e.userinfoEndpoint !== undefined &&
      (typeof e.userinfoEndpoint !== 'string' || !isHttpUrl(e.userinfoEndpoint))
    ) {
      throw new AuthError('AUTH_MISCONFIGURED', { detail: 'oauth: userinfoEndpoint must be an http(s) URL' })
    }
    if (
      e.revocationEndpoint !== undefined &&
      (typeof e.revocationEndpoint !== 'string' || !isHttpUrl(e.revocationEndpoint))
    ) {
      throw new AuthError('AUTH_MISCONFIGURED', { detail: 'oauth: revocationEndpoint must be an http(s) URL' })
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
  async exchangeCode(opts: { code: string; redirectUri: string; codeVerifier: string }): Promise<OAuth.TokenResponse> {
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
      // SECURITY: the scheme check above applies to this URL, not to wherever a redirect would land, and
      // a 307 re-posts this body -- `client_secret` included -- to whatever the `Location` names.
      redirect: 'error',
    })
    if (!res.ok) {
      const text = await res.text().catch(() => '')
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: 'oauth',
        detail: `token endpoint returned ${res.status}: ${text.slice(0, 200)}`,
      })
    }
    // Strict parse: a non-numeric `expires_in` would propagate NaN past every expiry check.
    const tokens = parseTokenResponse(await readJsonSafe(res))
    if (!tokens) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: 'oauth',
        detail: 'token endpoint returned malformed response',
      })
    }
    return tokens
  }

  /** Refresh-token rotation. Throws on any non-2xx. */
  async refresh(refreshToken: string): Promise<OAuth.TokenResponse> {
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
      // SECURITY: the scheme check above applies to this URL, not to wherever a redirect would land, and
      // a 307 re-posts this body -- `client_secret` included -- to whatever the `Location` names.
      redirect: 'error',
    })
    if (!res.ok) {
      const text = await res.text().catch(() => '')
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: 'oauth',
        detail: `refresh failed ${res.status}: ${text.slice(0, 200)}`,
      })
    }
    const tokens = parseTokenResponse(await readJsonSafe(res))
    if (!tokens) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: 'oauth',
        detail: 'refresh endpoint returned malformed response',
      })
    }
    return tokens
  }

  /** The provider may not expose one, in which case the profile comes from the id_token instead. */
  async userinfo(accessToken: string): Promise<Record<string, unknown>> {
    const e = await this._resolveEndpoints()
    if (!e.userinfoEndpoint) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'oauth: userinfoEndpoint not configured for this provider',
      })
    }
    const fetchImpl = this._opts.fetch ?? globalThis.fetch
    const res = await fetchImpl(e.userinfoEndpoint, {
      headers: { authorization: `Bearer ${accessToken}` },
      redirect: 'error',
    })
    if (!res.ok) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: 'oauth',
        detail: `userinfo failed ${res.status}`,
      })
    }
    // The body is IdP-controlled, so its shape is checked before any caller-supplied `fetchProfile` sees it.
    const json = await readJsonSafe(res)
    if (!isPlainObject(json)) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: 'oauth',
        detail: 'userinfo returned non-object body',
      })
    }
    return json
  }

  /** An authenticated GET of a JSON endpoint, under the same 64KB cap as {@link OAuthClient.userinfo}.
   *  For a provider whose profile needs a second call: GitHub keeps verified addresses on
   *  `/user/emails`, never on `/user`. The body is returned unnarrowed, because it is an array there
   *  and an object at userinfo. */
  async authedJson(url: string, accessToken: string, providerId = 'oauth'): Promise<unknown> {
    // SECURITY: reachable from a host's own `fetchProfile`, so the scheme is checked here for the same
    // reason `_resolveEndpoints` checks it -- a `file:` or `javascript:` URL must not reach fetch().
    if (!isHttpUrl(url)) {
      throw new AuthError('AUTH_MISCONFIGURED', { detail: 'oauth: authedJson url must be an http(s) URL' })
    }
    const fetchImpl = this._opts.fetch ?? globalThis.fetch
    const res = await fetchImpl(url, {
      headers: { authorization: `Bearer ${accessToken}` },
      redirect: 'error',
    })
    if (!res.ok) {
      throw new AuthError('AUTH_PROVIDER_FAILED', { providerId, detail: `authed request failed ${res.status}` })
    }
    return readJsonSafe(res)
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
  // Streamed and capped so a hostile IdP cannot OOM the process with a multi-GB body before JSON.parse is
  // ever reached. Real token and userinfo bodies are under 10KB, so 64KB is generous.
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

/** Validates an oauth2 token-endpoint response against RFC 6749 section 5.1. */
function parseTokenResponse(raw: unknown): OAuth.TokenResponse | null {
  if (!isPlainObject(raw)) return null
  const { access_token, token_type, expires_in, refresh_token, id_token, scope } = raw
  if (typeof access_token !== 'string' || access_token.length === 0) return null
  if (typeof token_type !== 'string' || token_type.length === 0) return null
  if (expires_in !== undefined && (typeof expires_in !== 'number' || !Number.isFinite(expires_in))) return null
  if (refresh_token !== undefined && typeof refresh_token !== 'string') return null
  if (id_token !== undefined && typeof id_token !== 'string') return null
  if (scope !== undefined && typeof scope !== 'string') return null
  const r: OAuth.TokenResponse = { access_token, token_type }
  if (expires_in !== undefined) r.expires_in = expires_in
  if (refresh_token !== undefined) r.refresh_token = refresh_token
  if (id_token !== undefined) r.id_token = id_token
  if (scope !== undefined) r.scope = scope
  return r
}
