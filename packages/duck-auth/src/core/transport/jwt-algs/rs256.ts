/**
 * RS256: RSA-SHA256 sign + verify via node:crypto.
 */

import { createSign, createVerify } from 'node:crypto'

export function signRs256(key: string, signingInput: string): string {
  const signer = createSign('RSA-SHA256')
  signer.update(signingInput)
  signer.end()
  return signer.sign(key).toString('base64url')
}

export function verifyRs256(key: string, signingInput: string, sigB64: string): boolean {
  const verifier = createVerify('RSA-SHA256')
  verifier.update(signingInput)
  verifier.end()
  return verifier.verify(key, Buffer.from(sigB64, 'base64url'))
}
