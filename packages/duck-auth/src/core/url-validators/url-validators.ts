import { AuthError } from '~/core/errors'
import { isBlockedHostname, isBlockedIpv4, isBlockedIpv6, parseIpv4, parseIpv6 } from './url-validators.constants'
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

/**
 * Refuse an outbound URL that points at loopback, a private range, link-local or cloud metadata.
 *
 * `label` names the setting in the error, because the only useful thing to say about a refused URL
 * is which piece of configuration carries it.
 *
 * This sees the spelling of a host and nothing else. A name that resolves inward is invisible to it
 * by construction; `assertResolvedHostIsPublic` is the half that needs a resolver.
 */
export function assertSafeOutboundUrl(rawUrl: string, opts: { label: string; allowInsecure?: boolean }): void {
  const { label } = opts
  const allowInsecure = opts.allowInsecure ?? false
  let parsed: URL
  try {
    parsed = new URL(rawUrl)
  } catch {
    throw new AuthError('AUTH_MISCONFIGURED', { detail: `${label} is not a valid URL: ${rawUrl}` })
  }
  if (parsed.protocol !== 'https:' && !(allowInsecure && parsed.protocol === 'http:')) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `${label} must use HTTPS (${parsed.protocol}). Pass allowInsecure: true for dev only.`,
    })
  }
  // Userinfo travels in the request line and in anything that records the endpoint afterwards, so a
  // secret written here leaks to every proxy, access log and dead-letter row on the path.
  if (parsed.username !== '' || parsed.password !== '') {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `${label} must not embed credentials in the URL; send them in a header instead`,
    })
  }
  assertSafeOutboundHost(parsed.hostname, label)
}

/**
 * Refuse a resolved address. The spelling guard cannot see where a name points, so a caller that
 * can resolve passes each answer through here before it connects.
 */
export function assertResolvedHostIsPublic(address: string, label: string): void {
  assertSafeOutboundHost(address, label)
}

function assertSafeOutboundHost(rawHost: string, label: string): void {
  const host = rawHost.toLowerCase()
  const v6 = parseIpv6(host)
  if (v6 === null ? classifyName(host) : isBlockedIpv6(v6)) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `${label} host ${host} is private / loopback / link-local - refused (SSRF guard)`,
    })
  }
}

function classifyName(host: string): boolean {
  const v4 = parseIpv4(host)
  return v4 === null ? isBlockedHostname(host) : isBlockedIpv4(v4)
}
