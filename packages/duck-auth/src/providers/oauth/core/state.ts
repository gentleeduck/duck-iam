import { createHmac, timingSafeEqual } from 'node:crypto'
import { randomToken } from '~/core/crypto'
import type { OAuth } from './oauth.types'

/** Signs a state payload into the `state` parameter the IdP round-trips. */
export function signState(payload: OAuth.StatePayload, secret: string): string {
  const json = JSON.stringify(payload)
  const body = Buffer.from(json, 'utf8').toString('base64url')
  const sig = createHmac('sha256', secret).update(body).digest('base64url')
  return `${body}.${sig}`
}

/** Null on signature mismatch or expiry, the payload otherwise. */
export function authVerifyState(
  state: string,
  secret: string,
  opts: { maxAgeMs?: number } = {},
): OAuth.StatePayload | null {
  const maxAgeMs = opts.maxAgeMs ?? 10 * 60 * 1000
  // Capped at 8KB so a multi-MB base64/JSON parse cannot be forced. The typeof holds because the caller
  // types this `string` while the wire surface is really unknown.
  if (typeof state !== 'string' || state.length === 0 || state.length > 8192) return null
  const [body, sig, ...rest] = state.split('.')
  if (rest.length > 0 || body === undefined || sig === undefined) return null
  const expected = createHmac('sha256', secret).update(body).digest('base64url')
  const a = Buffer.from(sig)
  const b = Buffer.from(expected)
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null
  let raw: unknown
  try {
    raw = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'))
  } catch {
    return null
  }
  const payload = parseStatePayload(raw)
  if (!payload) return null
  // Both ends: `now - iat > maxAgeMs` alone lets a future stamp yield a negative age and pass
  // forever, so a clock that jumps backwards makes every state minted before the jump immortal.
  const age = Date.now() - payload.iat
  if (age > maxAgeMs || age < -maxAgeMs) return null
  return payload
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** SECURITY: the state is HMAC-signed and carried in the provider's URL through the redirect dance, so an
 *  oversize `returnTo` blows up that URL, browsers capping near 2k and providers rejecting longer. Without
 *  the cap a hostile caller mints enormous state cookies through begin() that fail unpredictably. Real
 *  returnTo paths are tens of bytes, so 2048 is generous. */
const RETURN_TO_MAX = 2048

function parseStatePayload(raw: unknown): OAuth.StatePayload | null {
  if (!isPlainObject(raw)) return null
  const { nonce, verifier, providerId, binding, returnTo, iat } = raw
  if (typeof nonce !== 'string' || nonce.length === 0) return null
  if (typeof verifier !== 'string' || verifier.length === 0) return null
  if (typeof providerId !== 'string' || providerId.length === 0) return null
  // Required, not optional: a state minted before the binding existed would otherwise complete from
  // any browser, which is the thing the binding is for.
  if (typeof binding !== 'string' || binding.length === 0) return null
  if (typeof iat !== 'number' || !Number.isFinite(iat)) return null
  if (returnTo !== undefined) {
    if (typeof returnTo !== 'string') return null
    if (returnTo.length > RETURN_TO_MAX) return null
  }
  const payload: OAuth.StatePayload = { nonce, verifier, providerId, binding, iat }
  if (returnTo !== undefined) payload.returnTo = returnTo
  return payload
}

/** Builds a payload carrying a fresh nonce, the verifier, the providerId, and the digest of the cookie that
 *  binds it to one browser. */
export function authBuildState(
  providerId: string,
  verifier: string,
  opts: { binding: string; returnTo?: string },
): OAuth.StatePayload {
  const p: OAuth.StatePayload = {
    nonce: randomToken(16),
    verifier,
    providerId,
    binding: opts.binding,
    iat: Date.now(),
  }
  if (opts.returnTo !== undefined) p.returnTo = opts.returnTo
  return p
}
