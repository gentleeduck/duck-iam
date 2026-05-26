/**
 * @packageDocumentation
 * Sign in with Apple. The OAuth flow shape matches the rest of the
 * providers (PKCE-S256 + HMAC state + nonce) but Apple's client_secret
 * is a per-request ES256 JWT rather than a static string. This
 * provider generates the JWT on every token exchange so consumers do
 * not have to rotate one quarterly.
 *
 * Apple does NOT expose a userinfo endpoint. Profile comes from
 * decoding the id_token returned in the token response - sub + email
 * + email_verified are always present. The user-supplied name lands
 * in the `user` form param on the AUTHORIZATION call (Apple only
 * shares it on the very first consent), so capturing it requires app
 * cooperation; for now we surface sub + email which is sufficient for
 * the OAuthProvider profileToIdentityProfile hook.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { createSign } from 'node:crypto'
import type { Provider } from '../../../core/types/provider'
import { OAuthClient, type OAuthEndpoints } from '../core/client'
import { type OAuthBeginInput, type OAuthCompleteInput, type OAuthOptionsBase, oauthProvider } from '../core/provider'

const APPLE_ENDPOINTS: OAuthEndpoints = {
  authorizationEndpoint: 'https://appleid.apple.com/auth/authorize',
  tokenEndpoint: 'https://appleid.apple.com/auth/token',
  userinfoEndpoint: '',
  revocationEndpoint: 'https://appleid.apple.com/auth/revoke',
}

/**
 * Apple-specific options. `clientSecret` from `OAuthOptionsBase` is
 * ignored; the secret is generated per request from the team / key /
 * private-key triple.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface AppleOAuthOptions<Profile = unknown> extends Omit<OAuthOptionsBase<Profile>, 'clientSecret'> {
  /** Apple Developer Team ID (10-char alphanumeric). */
  teamId: string
  /** Key ID associated with the AuthKey_*.p8 file in Apple Developer. */
  keyId: string
  /**
   * The contents of the AuthKey_*.p8 file (ES256 private key, PEM).
   * Treat as a secret; load from a secrets manager.
   */
  privateKey: string
  /** Default `['name', 'email']`. */
  scopes?: string[]
}

/**
 * Generate a fresh Apple client_secret JWT. Valid for `ttlSec`
 * seconds; Apple caps at 6 months. We default to 30 minutes so the
 * exposed surface is tiny.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
function generateAppleClientSecret(
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
  if (der[0] !== 0x30) throw new Error('not a DER sequence')
  let offset = 2
  if ((der[1] ?? 0) & 0x80) offset = 2 + ((der[1] ?? 0) & 0x7f)
  if (der[offset] !== 0x02) throw new Error('expected r INTEGER')
  const rLen = der[offset + 1]!
  let r = der.subarray(offset + 2, offset + 2 + rLen)
  offset = offset + 2 + rLen
  if (der[offset] !== 0x02) throw new Error('expected s INTEGER')
  const sLen = der[offset + 1]!
  let s = der.subarray(offset + 2, offset + 2 + sLen)
  if (r[0] === 0 && r.length === halfLen + 1) r = r.subarray(1)
  if (s[0] === 0 && s.length === halfLen + 1) s = s.subarray(1)
  const rPad = Buffer.concat([Buffer.alloc(halfLen - r.length), r])
  const sPad = Buffer.concat([Buffer.alloc(halfLen - s.length), s])
  return Buffer.concat([rPad, sPad])
}

/** Decode an id_token payload (claims only; signature verification not done). */
function decodeIdToken(idToken: string): { sub: string; email?: string; email_verified?: boolean } | null {
  const parts = idToken.split('.')
  if (parts.length !== 3) return null
  try {
    return JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8'))
  } catch {
    return null
  }
}

/**
 * Sign in with Apple provider factory.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function apple<Profile = unknown>(
  opts: AppleOAuthOptions<Profile>,
): Provider.IProvider<OAuthBeginInput, OAuthCompleteInput, Profile> {
  const client = new OAuthClient({
    clientId: opts.clientId,
    clientSecret: '', // ignored - the OAuthClient uses the dynamic secret hook
    endpoints: APPLE_ENDPOINTS,
    scopes: opts.scopes ?? ['name', 'email'],
    ...(opts.fetch !== undefined && { fetch: opts.fetch }),
    // Replace the standard client_secret param with the freshly-minted
    // Apple JWT on every token exchange.
    dynamicClientSecret: () =>
      generateAppleClientSecret({
        teamId: opts.teamId,
        keyId: opts.keyId,
        privateKey: opts.privateKey,
        clientId: opts.clientId,
      }),
  })
  return oauthProvider<Profile>({
    providerId: 'apple',
    client,
    endpoints: APPLE_ENDPOINTS,
    redirectUri: opts.redirectUri,
    stateSigningSecret: opts.stateSigningSecret,
    ...(opts.onSignIn !== undefined && { onSignIn: opts.onSignIn }),
    ...(opts.profileToIdentityProfile !== undefined && {
      profileToIdentityProfile: opts.profileToIdentityProfile,
    }),
    async fetchProfile(tokens) {
      // Apple does not expose a userinfo endpoint; everything is in id_token.
      const tokenObj = tokens as { id_token?: string }
      if (!tokenObj.id_token) {
        return { sub: '' }
      }
      const claims = decodeIdToken(tokenObj.id_token)
      if (!claims) return { sub: '' }
      const out: { sub: string; email?: string; emailVerified?: boolean } = { sub: claims.sub }
      if (claims.email !== undefined) {
        out.email = claims.email
        // Apple only returns email_verified when the address is real
        // (not a private-relay alias). Treat private-relay aliases as
        // verified too - they cannot be created without Apple owning
        // the inbox.
        out.emailVerified = claims.email_verified ?? true
      }
      return out
    },
  })
}

/**
 * Namespace merge for `AppleOAuth`. Also exports the JWT helper for
 * callers who want to pre-mint the client_secret out-of-band.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace AppleOAuth {
  /** Alias for `AppleOAuthOptions`. */
  export type IOptions = AppleOAuthOptions
  /** Re-export of the client_secret JWT helper for advanced callers. */
  export const generateClientSecret = generateAppleClientSecret
}
