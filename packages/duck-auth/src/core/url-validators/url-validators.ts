/**
 * URL / path validators for outbound URL construction in recovery /
 * verification / deletion flows that produce links delivered to the
 * user via email or SMS.
 */

/**
 * Type predicate for a safe same-origin path suitable for concatenation
 * onto `baseUrl`. Rejects values that would let an attacker swap the
 * resulting URL's authority: missing leading `/`, protocol-relative
 * forms (`//`, `/\`), CR/LF injection, or out-of-bounds length.
 */
export function isSafeCallbackPath(value: unknown): value is string {
  if (typeof value !== 'string') return false
  if (value.length === 0 || value.length > 256) return false
  if (hasControlChar(value)) return false
  if (!value.startsWith('/')) return false
  if (value.startsWith('//')) return false
  if (value.startsWith('/\\')) return false
  return true
}

function hasControlChar(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c <= 0x1f || c === 0x7f) return true
  }
  return false
}
