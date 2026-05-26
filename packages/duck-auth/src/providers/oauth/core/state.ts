/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { createHmac, timingSafeEqual } from 'node:crypto'
import { randomToken } from '../../../core/crypto'

/**
 * Signed `state` parameter. Carries the PKCE verifier + an opaque nonce
 * tied to the user's pre-auth cookie so an attacker cannot stitch a
 * stolen authorisation code to a different browser.
 *
 * Encoding: `<payload-base64url>.<sig-base64url>`. HMAC-SHA256 over the
 * payload with the per-AuthRoot signing secret. Replay caught by single-
 * use nonce stored alongside the verifier in a transient session cache.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface StatePayload {
  /** Random nonce; one-time use. */
  nonce: string
  /** PKCE verifier - secret. Never leaves the server. */
  verifier: string
  /** Provider id; library refuses if it doesn't match the callback path. */
  providerId: string
  /** Optional return-to path on the app. Validated against allowedReturnTo. */
  returnTo?: string
  /** Issued-at; signer rejects after `maxAgeMs`. Default 10 minutes. */
  iat: number
}

export function signState(payload: StatePayload, secret: string): string {
  const json = JSON.stringify(payload)
  const body = Buffer.from(json, 'utf8').toString('base64url')
  const sig = createHmac('sha256', secret).update(body).digest('base64url')
  return `${body}.${sig}`
}

export function verifyState(state: string, secret: string, opts: { maxAgeMs?: number } = {}): StatePayload | null {
  const maxAgeMs = opts.maxAgeMs ?? 10 * 60 * 1000
  const parts = state.split('.')
  if (parts.length !== 2) return null
  const [body, sig] = parts as [string, string]
  const expected = createHmac('sha256', secret).update(body).digest('base64url')
  const a = Buffer.from(sig)
  const b = Buffer.from(expected)
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as StatePayload
    if (Date.now() - payload.iat > maxAgeMs) return null
    return payload
  } catch {
    return null
  }
}

export function buildState(providerId: string, verifier: string, opts: { returnTo?: string } = {}): StatePayload {
  const p: StatePayload = {
    nonce: randomToken(16),
    verifier,
    providerId,
    iat: Date.now(),
  }
  if (opts.returnTo !== undefined) p.returnTo = opts.returnTo
  return p
}
