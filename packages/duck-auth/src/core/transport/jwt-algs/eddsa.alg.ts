/**
 * EdDSA: Ed25519 sign + verify (RFC 8032).
 *
 * The KeyObject is required because Node's algorithm-less sign/verify
 * short-circuits when given a PEM string and the message length isn't
 * a multiple of 64.
 */

import { createPrivateKey, createPublicKey, sign as ed25519Sign, verify as ed25519Verify } from 'node:crypto'

export function signEddsa(key: string, signingInput: string): string {
  const pk = createPrivateKey(key)
  return ed25519Sign(null, Buffer.from(signingInput), pk).toString('base64url')
}

export function verifyEddsa(key: string, signingInput: string, sigB64: string): boolean {
  try {
    const pub = createPublicKey(key)
    return ed25519Verify(null, Buffer.from(signingInput), pub, Buffer.from(sigB64, 'base64url'))
  } catch {
    return false
  }
}
