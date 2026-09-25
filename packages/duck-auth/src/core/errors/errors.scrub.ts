import { isSecretKey } from '@gentleduck/error'

export { isSecretKey }

const DEPTH_CAP = 8

/**
 * Every secret-bearing value replaced by a marker, at any depth. The shape survives, the value does
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
