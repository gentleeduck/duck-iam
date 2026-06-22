/**
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
 * the AuthOAuthProvider profileToIdentityProfile hook.
 */

import { createSign } from 'node:crypto'
import type { AuthProvider } from '../../../core/types/provider'
import { AuthOAuthClient } from '../core/client'
import { type AuthOAuthProvider, oauthProvider } from '../core/provider'
import { getUserinfoBooleanTrue, getUserinfoString } from '../core/userinfo'

const APPLE_ENDPOINTS: AuthOAuthClient.IEndpoints = {
  authorizationEndpoint: 'https://appleid.authApple.com/auth/authorize',
  tokenEndpoint: 'https://appleid.authApple.com/auth/token',
  userinfoEndpoint: '',
  revocationEndpoint: 'https://appleid.authApple.com/auth/revoke',
}

export namespace AuthAppleOAuth {
  /**
   * Apple-specific options. `clientSecret` from
   * `AuthOAuthProvider.IOptionsBase` is ignored; the secret is generated
   * per request from the team / key / private-key triple.
   */
  export interface IOptions<Profile = unknown> extends Omit<AuthOAuthProvider.IOptionsBase<Profile>, 'clientSecret'> {
    /** Apple Developer Team ID (10-char alphanumeric). */
    teamId: string
    /** Key ID associated with the AuthKey_*.p8 file. */
    keyId: string
    /**
     * The contents of the AuthKey_*.p8 file (ES256 private key, PEM).
     * Treat as a secret; load from a secrets manager.
     */
    privateKey: string
    /** Default `['name', 'email']`. */
    scopes?: string[]
  }
}

/**
 * Generate a fresh Apple client_secret JWT. Valid for `ttlSec`
 * seconds; Apple caps at 6 months. We default to 30 minutes so the
 * exposed surface is tiny.
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
    aud: 'https://appleid.authApple.com',
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
  const rLen = der.readUInt8(offset + 1)
  let r = der.subarray(offset + 2, offset + 2 + rLen)
  offset = offset + 2 + rLen
  if (der[offset] !== 0x02) throw new Error('expected s INTEGER')
  const sLen = der.readUInt8(offset + 1)
  let s = der.subarray(offset + 2, offset + 2 + sLen)
  if (r[0] === 0 && r.length === halfLen + 1) r = r.subarray(1)
  if (s[0] === 0 && s.length === halfLen + 1) s = s.subarray(1)
  const rPad = Buffer.concat([Buffer.alloc(halfLen - r.length), r])
  const sPad = Buffer.concat([Buffer.alloc(halfLen - s.length), s])
  return Buffer.concat([rPad, sPad])
}

/** Decode + shape-validate an Apple id_token payload (signature is verified upstream by TLS+client_secret). */
export function authDecodeIdToken(idToken: string): { sub: string; email?: string; email_verified?: boolean } | null {
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
  // Apple's claim is sometimes string `"true"` instead of boolean -
  // accept either for the verified case, but use strict checks.
  if (getUserinfoBooleanTrue(raw, 'email_verified')) {
    out.email_verified = true
  } else if (typeof raw === 'object' && raw !== null && Reflect.get(raw, 'email_verified') === 'true') {
    // Apple specifically: string-encoded boolean. RFC 7519 doesn't
    // mandate booleans for custom claims, so we accept both forms.
    out.email_verified = true
  }
  return out
}

/** Sign in with Apple provider factory. */
export function authApple<Profile = unknown>(
  opts: AuthAppleOAuth.IOptions<Profile>,
): AuthProvider.IProvider<AuthOAuthProvider.IBeginInput, AuthOAuthProvider.ICompleteInput, Profile> {
  const client = new AuthOAuthClient({
    clientId: opts.clientId,
    clientSecret: '', // ignored - the AuthOAuthClient uses the dynamic secret hook
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
    providerId: 'authApple',
    client,
    endpoints: APPLE_ENDPOINTS,
    redirectUri: opts.redirectUri,
    stateSigningSecret: opts.stateSigningSecret,
    ...(opts.onSignIn !== undefined && { onSignIn: opts.onSignIn }),
    ...(opts.profileToIdentityProfile !== undefined && {
      profileToIdentityProfile: opts.profileToIdentityProfile,
    }),
    async fetchProfile(tokens) {
      // Apple has no userinfo endpoint; everything is in id_token.
      if (!tokens.id_token) {
        return { sub: '' }
      }
      const claims = authDecodeIdToken(tokens.id_token)
      if (!claims) return { sub: '' }
      const out: { sub: string; email?: string; emailVerified?: boolean } = { sub: claims.sub }
      if (claims.email !== undefined) {
        out.email = claims.email
        // Treat relay aliases as verified; only Apple can create them.
        out.emailVerified = claims.email_verified ?? true
      }
      return out
    },
  })
}

export namespace AuthAppleOAuth {
  /** Re-export of the client_secret JWT helper for advanced callers. */
  export const generateClientSecret = generateAppleClientSecret
}
