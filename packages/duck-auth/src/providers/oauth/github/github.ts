import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import { OAuthClient } from '../core/client'
import type { OAuth } from '../core/oauth.types'
import { oProvider } from '../core/provider'
import { getUserinfoBooleanTrue, getUserinfoNumericIdAsString, getUserinfoString } from '../core/userinfo'

const GITHUB_ENDPOINTS: OAuth.Endpoints = {
  authorizationEndpoint: 'https://github.com/login/oauth/authorize',
  tokenEndpoint: 'https://github.com/login/oauth/access_token',
  userinfoEndpoint: 'https://api.github.com/user',
}

/** What the `user:email` scope grants. `/user` carries only the public profile address, which GitHub
 *  leaves unset by default and never marks as verified. */
const GITHUB_EMAILS_ENDPOINT = 'https://api.github.com/user/emails'

/**
 * The account's primary verified address, or `undefined` when there is none to be had.
 *
 * Best effort by design: the address enriches the profile and does not gate sign-in, so a token
 * without `user:email`, a rate-limited API or an account with no verified address all fall back to the
 * public profile email rather than failing the sign-in. Verification is read from GitHub, never assumed:
 * only a row that is both `primary` and `verified` answers here, which is what lets
 * `onFederationConflict: 'link-if-verified'` fire for this provider at all.
 */
async function primaryVerifiedEmail(c: OAuthClient, accessToken: string): Promise<string | undefined> {
  let rows: unknown
  try {
    rows = await c.authedJson(GITHUB_EMAILS_ENDPOINT, accessToken, 'authGithub')
  } catch {
    return undefined
  }
  if (!Array.isArray(rows)) return undefined
  for (const row of rows) {
    if (!getUserinfoBooleanTrue(row, 'primary') || !getUserinfoBooleanTrue(row, 'verified')) continue
    const email = getUserinfoString(row, 'email')
    if (email !== undefined) return email
  }
  return undefined
}

/** GitHub oauth 2.0 provider. */
export function github<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  opts: OAuth.GithubOptions<Profile>,
): Provider.Me<OAuth.BeginInput, OAuth.CompleteInput, Profile> {
  const client = new OAuthClient({
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
    endpoints: GITHUB_ENDPOINTS,
    scopes: opts.scopes ?? ['read:user', 'user:email'],
    fetch: opts.fetch,
  })
  return oProvider<Profile>({
    providerId: 'authGithub',
    client,
    endpoints: GITHUB_ENDPOINTS,
    redirectUri: opts.redirectUri,
    stateSigningSecret: opts.stateSigningSecret,
    nonceStore: opts.nonceStore,
    allowStateReplay: opts.allowStateReplay,
    stateCookie: opts.stateCookie,
    onSignIn: opts.onSignIn,
    onFederationConflict: opts.onFederationConflict,
    profileToIdentityProfile: opts.profileToIdentityProfile,
    async fetchProfile(tokens, c) {
      const info = await c.userinfo(tokens.access_token)
      // `String(info.id)` on a null id would collide every bad id onto the one sub `'null'`.
      const sub = getUserinfoNumericIdAsString(info, 'id')
      if (sub === undefined) {
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          providerId: 'authGithub',
          detail: 'GitHub userinfo missing numeric id',
        })
      }
      const out: { sub: string; email?: string; emailVerified?: boolean; name?: string; avatarUrl?: string } = { sub }
      const verified = await primaryVerifiedEmail(c, tokens.access_token)
      if (verified !== undefined) {
        out.email = verified
        out.emailVerified = true
      } else {
        // Carried, never asserted as verified: `/user` says nothing about verification, so this takes
        // the same posture as Microsoft's.
        const email = getUserinfoString(info, 'email')
        if (email !== undefined) out.email = email
      }
      const name = getUserinfoString(info, 'name')
      if (name !== undefined) out.name = name
      const avatar = getUserinfoString(info, 'avatar_url')
      if (avatar !== undefined) out.avatarUrl = avatar
      return out
    },
  })
}
