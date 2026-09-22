/** What may not reach the wire, by key name. */
const SECRET_KEY =
  /secret|password|passphrase|plaintext|token|hash|salt|signature|credential|private|otp|recovery|apikey|api_key/i

const DEPTH_CAP = 8

/** Whether a key name may not reach the wire. */
export function isSecretKey(key: string): boolean {
  return SECRET_KEY.test(key)
}

/**
 * Every secret-bearing key replaced by a marker, at any depth. The shape survives, the value does
 * not, which is what a consumer reading someone else's payload shape needs. Past the cap the subtree
 * is truncated, not walked.
 */
export function redactSecrets(value: unknown, depth = 0): unknown {
  // SECURITY: truncated at the cap, not handed back. Returning `value` here returned a whole unwalked
  // subtree, so anything nested past the cap carried its secrets out in full while the redaction read as
  // if it had run - and this one guards a webhook POST to somebody else's server.
  if (depth > DEPTH_CAP) return '[depth-cap]'
  if (value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) return value.map((item) => redactSecrets(item, depth + 1))
  if (value instanceof Date) return value
  const out: Record<string, unknown> = {}
  for (const [key, item] of Object.entries(value)) {
    out[key] = isSecretKey(key) ? '[redacted]' : redactSecrets(item, depth + 1)
  }
  return out
}

/** Every secret-bearing key dropped, at any depth. Past the cap the subtree is truncated, not walked. */
export function scrubMeta(meta: object, depth = 0): Record<string, unknown> {
  const safe: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(meta)) {
    if (!isSecretKey(key)) safe[key] = scrubValue(value, depth + 1)
  }
  return safe
}

function scrubValue(value: unknown, depth: number): unknown {
  if (depth > DEPTH_CAP) return '[depth-cap]'
  if (Array.isArray(value)) return value.map((item) => scrubValue(item, depth + 1))
  if (value instanceof Date) return value
  if (typeof value === 'object' && value !== null) return scrubMeta(value, depth)
  return value
}
