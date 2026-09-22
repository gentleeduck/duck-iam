import { orNull } from '~/core/answer'
import { toCredentialCreate } from '~/core/credentials/credentials'
import { randomToken, sha256, timingSafeEqual } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import { parseCookie } from '~/core/transport'
import type { OAuth } from './oauth.types'
import { generatePkce } from './pkce'
import { authBuildState, authVerifyState, signState } from './state'

/** Must not outlive the state's own max age, or the cookie expires mid-flow and the callback fails. */
const STATE_COOKIE_MAX_AGE_SEC = 600

/** The generic oauth provider. Each provider module pre-fills endpoints, scopes and `fetchProfile`, then
 *  re-exports this. */
export class OProviderImpl<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>
  implements Provider.Me<OAuth.BeginInput, OAuth.CompleteInput, Profile>
{
  readonly id: string
  readonly kind = 'oauth' as const
  /** Read by `strict()`, which enforces the production floor. A boolean, never the secret. */
  readonly __weakStateSecret: boolean
  private readonly _cookieName: string
  private readonly _cookieOptions: Provider.CookieOptions

  constructor(private readonly opts: OAuth.Options<Profile>) {
    this.id = `oauth:${opts.providerId}`
    // SECURITY: `createHmac` accepts an empty key and produces a valid MAC with it, so an absent secret
    // is not an unsigned state, it is a state anyone can sign. Refused here rather than at first use.
    if (typeof opts.stateSigningSecret !== 'string' || opts.stateSigningSecret.length === 0) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `oauth.stateSigningSecret must be a non-empty string (provider ${opts.providerId})`,
      })
    }
    // RFC 7518 section 3.2: an HMAC-SHA256 key must be at least as long as the hash it feeds.
    this.__weakStateSecret = Buffer.byteLength(opts.stateSigningSecret, 'utf8') < 32
    const cookie = opts.stateCookie ?? {}
    this._cookieName = cookie.name ?? (cookie.domain === undefined ? '__Host-duck-oauth' : 'duck-oauth')
    const secure = cookie.secure ?? true
    this._cookieOptions = {
      httpOnly: true,
      // The callback is a top-level GET the IdP navigates to. 'lax' sends the cookie on that and
      // 'strict' does not, which would refuse every real sign-in.
      sameSite: 'lax',
      secure,
      path: '/',
      maxAge: STATE_COOKIE_MAX_AGE_SEC,
      ...(cookie.domain !== undefined && { domain: cookie.domain }),
    }
    // Browsers drop a `__Host-` cookie that breaks either rule without saying so, and a silently
    // dropped cookie here is every sign-in failing at the callback.
    if (this._cookieName.startsWith('__Host-') && (cookie.domain !== undefined || !secure)) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail:
          'oauth.stateCookie: the __Host- prefix forbids a domain and requires secure; name it something else for an http host',
      })
    }
    // Refused at construction so a `javascript:alert(1)`, an unparseable string, or one carrying CR/LF for
    // header injection never reaches the IdP authorize URL or the session-issue path.
    if (!isValidoauthRedirectUri(opts.redirectUri)) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `oauth.redirectUri must be an http(s) URL with no CR/LF (got: ${typeof opts.redirectUri})`,
      })
    }
  }

  async begin(_ctx: Provider.Context<Profile>, input: OAuth.BeginInput): Promise<Provider.Intent[]> {
    const pkce = generatePkce()
    // The state is signed but not secret: it travels to the IdP and back in a URL, so it says who
    // began a flow and not who is finishing one. This cookie is the half the IdP never sees.
    const binding = randomToken(32)
    const statePayload = authBuildState(this.id, pkce.verifier, {
      binding: sha256(binding),
      ...(input?.returnTo !== undefined && { returnTo: input.returnTo }),
    })
    const state = signState(statePayload, this.opts.stateSigningSecret)
    const url = await this.opts.client.buildAuthorizeUrl({
      redirectUri: this.opts.redirectUri,
      state,
      codeChallenge: pkce.challenge,
    })
    return [
      { type: 'setCookie', name: this._cookieName, value: binding, options: this._cookieOptions },
      { type: 'redirect', url, status: 302 },
    ]
  }

  async complete(ctx: Provider.Context<Profile>, input: OAuth.CompleteInput): Promise<Provider.InternalIntent[]> {
    // Caps `code` at 2KB, so this cannot be used to amplify outbound traffic at the IdP.
    if (typeof input.code !== 'string' || input.code.length === 0 || input.code.length > 2048) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: this.id,
        detail: 'invalid authorization code',
      })
    }
    const verified = authVerifyState(input.state, this.opts.stateSigningSecret)
    if (!verified) {
      throw new AuthError('AUTH_OAUTH_STATE_MISMATCH')
    }
    if (verified.providerId !== this.id) {
      throw new AuthError('AUTH_OAUTH_STATE_MISMATCH')
    }
    // Without this a signed state completes from any browser, so an attacker who begins a flow can
    // hand the callback URL to a victim and have the victim's browser sign in as the attacker.
    const presented = typeof input.cookieHeader === 'string' ? parseCookie(input.cookieHeader, this._cookieName) : null
    if (presented === null || !timingSafeEqual(sha256(presented), verified.binding)) {
      throw new AuthError('AUTH_OAUTH_STATE_MISMATCH')
    }

    const tokens = await this.opts.client.exchangeCode({
      code: input.code,
      redirectUri: this.opts.redirectUri,
      codeVerifier: verified.verifier,
    })
    const profile = await this.opts.fetchProfile(tokens, this.opts.client)
    if (!profile.sub || profile.sub.length === 0) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: this.id,
        detail: 'oauth profile missing sub',
      })
    }

    let identityId: string | null = null
    if (this.opts.onSignIn) {
      const r = await this.opts.onSignIn({
        profile,
        findByProviderSub: (sub) => orNull(ctx.stores.identities.find({ providerId: this.id, providerSub: sub })),
        findByEmail: (email) => orNull(ctx.stores.identities.find({ email })),
        createIdentity: async (p) => {
          const created = await ctx.stores.identities.create({
            profile: p,
            providers: [{ providerId: this.id, providerSub: profile.sub }],
            emailVerified: false,
          })
          return { id: created.id }
        },
        linkProvider: async (id, sub) => {
          await ctx.stores.identities.link(id, {
            providerId: this.id,
            providerSub: sub,
          })
        },
      })
      if (!r) {
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId: this.id,
          detail: 'sign-in refused by onSignIn callback',
        })
      }
      identityId = r.identityId
    } else {
      const bySub = await orNull(ctx.stores.identities.find({ providerId: this.id, providerSub: profile.sub }))
      if (bySub) {
        identityId = bySub.id
      } else if (profile.email) {
        const byEmail = await orNull(ctx.stores.identities.find({ email: profile.email }))
        if (byEmail) {
          // Email matches but no sub link; silent auto-link is ATO bait.
          const policy = this.opts.onFederationConflict ?? 'reject'
          const verdict = await resolveFederationConflict(policy, {
            existingIdentityId: byEmail.id,
            profile,
            providerId: this.id,
          })
          if (verdict === 'reject') {
            throw new AuthError('AUTH_PROVIDER_FAILED', {
              providerId: this.id,
              detail:
                'federation-conflict: an existing identity owns this email; provider-sub link refused under the configured policy',
            })
          }
          await ctx.stores.identities.link(byEmail.id, {
            providerId: this.id,
            providerSub: profile.sub,
          })
          identityId = byEmail.id
        }
      }
      if (!identityId) {
        const projected = this.opts.profileToIdentityProfile?.(profile)
        if (!projected) {
          throw new AuthError('AUTH_PROVIDER_FAILED', {
            providerId: this.id,
            detail: 'profileToIdentityProfile rejected the profile',
          })
        }
        const created = await ctx.stores.identities.create({
          profile: projected,
          providers: [{ providerId: this.id, providerSub: profile.sub }],
          emailVerified: false,
        })
        identityId = created.id
      }
    }

    if (tokens.refresh_token) {
      const familyId = `${this.id}:${profile.sub}:${sha256(input.code).slice(0, 16)}`
      await ctx.stores.credentials.create(
        toCredentialCreate({
          identityId,
          kind: 'oauth',
          secret: sha256(tokens.refresh_token),
          metadata: {
            provider: this.id,
            sub: profile.sub,
            familyId,
            generation: 1,
          } satisfies OAuth.CredentialMetadata,
        }),
        ctx.tenant,
      )
    }

    return [
      // Spent. The state stays verifiable until it ages out, so leaving the cookie behind leaves a
      // callback URL that still works if it is recovered from history or a referrer.
      { type: 'clearCookie', name: this._cookieName, options: { ...this._cookieOptions, maxAge: 0 } },
      {
        type: 'startSession',
        identityId,
        factors: [{ method: 'oauth', completedAt: new Date() }],
        aal: 1,
      },
    ]
  }
}

export function oProvider<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  opts: OAuth.Options<Profile>,
): Provider.Me<OAuth.BeginInput, OAuth.CompleteInput, Profile> {
  return new OProviderImpl(opts)
}

/** Module-local so no caller can bypass `'link-if-verified'`, which needs both an `emailVerified` of true and
 *  an unambiguous email match. */
async function resolveFederationConflict(
  policy: OAuth.FederationPolicy,
  ctx: { existingIdentityId: string; profile: OAuth.Profile; providerId: string },
): Promise<'link' | 'reject'> {
  if (policy === 'reject') return 'reject'
  if (policy === 'link-if-verified') {
    return ctx.profile.emailVerified === true ? 'link' : 'reject'
  }
  // Anything other than the documented `'link' | 'reject'` is refused, so a typo'd return cannot fall through
  // to 'link', which is the dangerous one.
  const verdict = await policy(ctx)
  return verdict === 'link' ? 'link' : 'reject'
}

function isValidoauthRedirectUri(value: unknown): value is string {
  if (typeof value !== 'string') return false
  if (value.length === 0 || value.length > 2048) return false
  if (value.includes('\r') || value.includes('\n')) return false
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    return false
  }
  return parsed.protocol === 'https:' || parsed.protocol === 'http:'
}
