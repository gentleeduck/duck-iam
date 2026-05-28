import { createHash, randomBytes } from 'node:crypto'

/**
 * RFC 7636 PKCE - Proof Key for Code Exchange. We always use `S256`
 * (the legacy `plain` method is forbidden by `strict()` in production).
 */
export function generatePkce(): { verifier: string; challenge: string; method: 'S256' } {
  // 43-128 chars, base64url, generated from 32 random bytes.
  const verifier = randomBytes(32).toString('base64url')
  const challenge = createHash('sha256').update(verifier).digest('base64url')
  return { verifier, challenge, method: 'S256' }
}
