import { createHmac, timingSafeEqual } from 'node:crypto'
import { randomToken } from '~/core/crypto'
import type { OAuth } from './oauth.types'

/** Sign a state payload into the oauth `state` parameter string. */
export function signState(payload: OAuth.StatePayload, secret: string): string {
  const json = JSON.stringify(payload)
  const body = Buffer.from(json, 'utf8').toString('base64url')
  const sig = createHmac('sha256', secret).update(body).digest('base64url')
  return `${body}.${sig}`
}

/**
 * Verify a signed `state` parameter. Returns the payload on success,
 * null on signature mismatch or expiry.
 */
export function authVerifyState(
  state: string,
  secret: string,
  opts: { maxAgeMs?: number } = {},
): OAuth.StatePayload | null {
  const maxAgeMs = opts.maxAgeMs ?? 10 * 60 * 1000
  // 8KB cap on `state` to prevent multi-MB base64/JSON parse DoS.
  // Defensive typeof: caller types it `string` but the wire surface is `unknown`.
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
  if (Date.now() - payload.iat > maxAgeMs) return null
  return payload
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** SEC: hard cap on returnTo length. The state is HMAC-signed + carried
 * in the oauth provider's URL on the redirect dance; an oversize value
 * blows up the URL (browsers cap at ~2k, providers reject longer). Cap
 * here so a hostile caller cannot use begin() to mint enormous state
 * cookies / URLs that fail unpredictably. 2048 is generous - real
 * returnTo paths are tens of bytes. */
const RETURN_TO_MAX = 2048

function parseStatePayload(raw: unknown): OAuth.StatePayload | null {
  if (!isPlainObject(raw)) return null
  const { nonce, verifier, providerId, returnTo, iat } = raw
  if (typeof nonce !== 'string' || nonce.length === 0) return null
  if (typeof verifier !== 'string' || verifier.length === 0) return null
  if (typeof providerId !== 'string' || providerId.length === 0) return null
  if (typeof iat !== 'number' || !Number.isFinite(iat)) return null
  if (returnTo !== undefined) {
    if (typeof returnTo !== 'string') return null
    if (returnTo.length > RETURN_TO_MAX) return null
  }
  const payload: OAuth.StatePayload = { nonce, verifier, providerId, iat }
  if (returnTo !== undefined) payload.returnTo = returnTo
  return payload
}

/**
 * Build a fresh state payload with a random nonce + the given verifier
 * + providerId.
 */
export function authBuildState(
  providerId: string,
  verifier: string,
  opts: { returnTo?: string } = {},
): OAuth.StatePayload {
  const p: OAuth.StatePayload = {
    nonce: randomToken(16),
    verifier,
    providerId,
    iat: Date.now(),
  }
  if (opts.returnTo !== undefined) p.returnTo = opts.returnTo
  return p
}
