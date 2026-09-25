/**
 * Sign in with Apple. The flow shape matches the other providers (PKCE-S256 + HMAC-signed state), but the
 * client_secret is a per-request ES256 JWT rather than a static string, minted on every token exchange so
 * nothing has to be rotated quarterly.
 */

import { createSign } from 'node:crypto'
import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import { OAuthClient } from '../core/client'
import type { OAuth } from '../core/oauth.types'
import { oProvider } from '../core/provider'
import { getUserinfoBooleanTrue, getUserinfoString } from '../core/userinfo'

/** Apple exposes no userinfo endpoint, so the key is absent rather than `''`: the client validates every
 *  endpoint it is given as an http(s) URL, and an empty string is a string. Spelled `''` this threw
 *  `AUTH_MISCONFIGURED` out of `buildAuthorizeUrl`, which is to say no Apple flow could begin at all. */
const APPLE_ENDPOINTS: OAuth.Endpoints = {
  authorizationEndpoint: 'https://appleid.apple.com/auth/authorize',
  revocationEndpoint: 'https://appleid.apple.com/auth/revoke',
  tokenEndpoint: 'https://appleid.apple.com/auth/token',
}

/** Valid for `ttlSec` seconds, which Apple caps at 6 months; the 30 minute default keeps the window small. */
export function generateClientSecret(
  opts: { teamId: string; keyId: string; privateKey: string; clientId: string },
  ttlSec = 30 * 60,
): string {
  const now = Math.floor(Date.now() / 1000)
  const header = { alg: 'ES256', kid: opts.keyId, typ: 'JWT' }
  const payload = {
    iss: opts.teamId,
    iat: now,
    exp: now + ttlSec,
    aud: 'https://appleid.apple.com',
    sub: opts.clientId,
  }
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const signingInput = `${headerB64}.${payloadB64}`
  const signer = createSign('SHA256')
  signer.update(signingInput)
  signer.end()
  const der = signer.sign(opts.privateKey)
  // Apple wants r||s (JOSE format), not DER.
  const sig = derToJose(der, 32)
  return `${signingInput}.${sig.toString('base64url')}`
}

/** DER -> r||s for ES256 signatures. */
function derToJose(der: Buffer, halfLen: number): Buffer {
  if (der[0] !== 0x30) throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'not a DER sequence' })
  let offset = 2
  if ((der[1] ?? 0) & 0x80) offset = 2 + ((der[1] ?? 0) & 0x7f)
  if (der[offset] !== 0x02) throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'expected r INTEGER' })
  const rLen = der.readUInt8(offset + 1)
  let r = der.subarray(offset + 2, offset + 2 + rLen)
  offset = offset + 2 + rLen
  if (der[offset] !== 0x02) throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'expected s INTEGER' })
  const sLen = der.readUInt8(offset + 1)
  let s = der.subarray(offset + 2, offset + 2 + sLen)
  if (r[0] === 0 && r.length === halfLen + 1) r = r.subarray(1)
  if (s[0] === 0 && s.length === halfLen + 1) s = s.subarray(1)
  const rPad = Buffer.concat([Buffer.alloc(halfLen - r.length), r])
  const sPad = Buffer.concat([Buffer.alloc(halfLen - s.length), s])
  return Buffer.concat([rPad, sPad])
}

/** Decode + shape-validate an Apple id_token payload (signature is verified upstream by TLS+client_secret). */
export function decodeIdToken(idToken: string): { sub: string; email?: string; email_verified?: boolean } | null {
  const parts = idToken.split('.')
  if (parts.length !== 3) return null
  let raw: unknown
  try {
    raw = JSON.parse(Buffer.from(parts[1] ?? '', 'base64url').toString('utf8'))
  } catch {
    return null
  }
  const sub = getUserinfoString(raw, 'sub')
  if (sub === undefined) return null
  const out: { sub: string; email?: string; email_verified?: boolean } = { sub }
  const email = getUserinfoString(raw, 'email')
  if (email !== undefined) out.email = email
  // Apple sends `email_verified` as the string `"true"` as often as the boolean, and RFC 7519 does not
  // mandate booleans for custom claims, so both forms count; anything else does not.
  if (getUserinfoBooleanTrue(raw, 'email_verified')) {
    out.email_verified = true
  } else if (typeof raw === 'object' && raw !== null && Reflect.get(raw, 'email_verified') === 'true') {
    out.email_verified = true
  }
  return out
}

/** Sign in with Apple provider. */
export function apple<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  opts: OAuth.AppleOptions<Profile>,
): Provider.Me<OAuth.BeginInput, OAuth.CompleteInput, Profile> {
  const client = new OAuthClient({
    clientId: opts.clientId,
    clientSecret: '', // ignored; the client uses the dynamic secret hook below
    endpoints: APPLE_ENDPOINTS,
    scopes: opts.scopes ?? ['name', 'email'],
    fetch: opts.fetch,
    // Replaces the standard client_secret param on every token exchange.
    dynamicClientSecret: () =>
      generateClientSecret({
        teamId: opts.teamId,
        keyId: opts.keyId,
        privateKey: opts.privateKey,
        clientId: opts.clientId,
      }),
  })
  return oProvider<Profile>({
    providerId: 'authApple',
    client,
    endpoints: APPLE_ENDPOINTS,
    // Apple switches to a form post as soon as any scope is requested, and the default scopes are
    // `['name', 'email']`. Without this the callback never arrives in the shape the flow expects.
    responseMode: 'form_post',
    redirectUri: opts.redirectUri,
    stateSigningSecret: opts.stateSigningSecret,
    nonceStore: opts.nonceStore,
    allowStateReplay: opts.allowStateReplay,
    stateCookie: opts.stateCookie,
    onSignIn: opts.onSignIn,
    onFederationConflict: opts.onFederationConflict,
    profileToIdentityProfile: opts.profileToIdentityProfile,
    async fetchProfile(tokens) {
      // Apple has no userinfo endpoint; everything is in id_token.
      if (!tokens.id_token) {
        return { sub: '' }
      }
      const claims = decodeIdToken(tokens.id_token)
      if (!claims) return { sub: '' }
      const out: { sub: string; email?: string; emailVerified?: boolean } = { sub: claims.sub }
      if (claims.email !== undefined) {
        out.email = claims.email
        // SECURITY: the claim Apple sent, never an absent one read as `true`. This is the flag
        // `onFederationConflict: 'link-if-verified'` keys on to hand an existing account to whoever
        // presents its address, so defaulting it open linked on the strength of a claim that was not
        // there.
        if (claims.email_verified === true) out.emailVerified = true
      }
      return out
    },
  })
}
