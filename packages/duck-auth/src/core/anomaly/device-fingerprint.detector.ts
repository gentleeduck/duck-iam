/** Device-fingerprint detector: emit `new-device` on first sight of (identity, ua+ipSubnet). */

import { AuthError } from '~/core/errors'
import type { Anomaly } from './anomaly.types'

/** Reference in-memory device-fingerprint store; production wires Redis. */
export class AuthMemoryDeviceFingerprintStore implements AuthDeviceFingerprint.IStore {
  /** Insertion-ordered, so the oldest entry is the first the cap evicts. */
  private readonly _known = new Map<string, Map<string, number>>()
  private readonly _maxPerIdentity: number
  private readonly _ttlMs: number

  /**
   * One request per rotated user agent used to grow the set without bound, and this is the
   * reference implementation the default wiring reaches for. Bounded both ways: entries expire, and
   * the oldest is evicted once an identity holds `maxPerIdentity` of them.
   */
  constructor(cfg: { maxPerIdentity?: number; ttlMs?: number } = {}) {
    this._maxPerIdentity = cfg.maxPerIdentity ?? MEMORY_MAX_PER_IDENTITY
    this._ttlMs = cfg.ttlMs ?? MEMORY_TTL_MS
  }

  /**
   * Atomic check-and-insert. Returns true when the fingerprint was
   * already known; false on first sight.
   */
  async checkAndRemember(identityId: string, fingerprint: string): Promise<boolean> {
    const now = Date.now()
    let seen = this._known.get(identityId)
    if (!seen) {
      seen = new Map()
      this._known.set(identityId, seen)
    }
    for (const [fp, at] of seen) {
      if (now - at > this._ttlMs) seen.delete(fp)
    }
    if (seen.has(fingerprint)) {
      seen.set(fingerprint, now)
      return true
    }
    seen.set(fingerprint, now)
    while (seen.size > this._maxPerIdentity) {
      const oldest = seen.keys().next().value
      if (oldest === undefined) break
      seen.delete(oldest)
    }
    return false
  }

  /**
   * Wipe every fingerprint for an identity. Used by sign-out-of-all
   * flows + after a forced credential reset.
   */
  async forgetAll(identityId: string): Promise<void> {
    this._known.delete(identityId)
  }

  /** Undo one sighting. See {@link AuthDeviceFingerprint.IStore.forget}. */
  async forget(identityId: string, fingerprint: string): Promise<void> {
    this._known.get(identityId)?.delete(fingerprint)
  }
}

/** Devices one identity may be remembered on before the oldest is evicted. */
const MEMORY_MAX_PER_IDENTITY = 50
/** How long a sighting counts as recent. 90 days, matching the usual "remember this device" span. */
const MEMORY_TTL_MS = 90 * 24 * 60 * 60 * 1000

const UA_MAX_LENGTH = 1024
const IP_MAX_LENGTH = 64

/**
 * The bucket a request that declines to identify itself lands in.
 *
 * SECURITY: these used to make `defaultCompose` return null, which switched the detector off for
 * that request. Sending no User-Agent, or padding it past the cap, is entirely the caller's choice
 * and is the one thing no real browser does, so the evasion was both free and the exact opposite of
 * the signal it suppressed. One shared bucket instead: the first such request is a new device and
 * raises its signal, and the rest are the same device, which is what they look like.
 */
const ABSENT = '\u0000absent'
const UNPARSED = '\u0000unparsed'

/** authSha256(`${ua}|${ipSubnet}`); /24 IPv4, /48 IPv6. Roaming-tolerant, ISP-sensitive. */
function defaultCompose(req: Anomaly.RequestSnapshot, authSha256: (s: string) => string): string | null {
  return authSha256(`${uaKey(req.userAgent?.trim())}|${ipKey(req.ip?.trim())}`)
}

function uaKey(ua: string | undefined): string {
  if (!ua) return ABSENT
  // Truncated rather than refused. The cap is here to bound the hash input, and bounding it does not
  // require declining to fingerprint the request.
  return ua.length > UA_MAX_LENGTH ? ua.slice(0, UA_MAX_LENGTH) : ua
}

function ipKey(ip: string | undefined): string {
  if (!ip) return ABSENT
  if (ip.length > IP_MAX_LENGTH) return UNPARSED
  return ipSubnet(ip)
}

function isOctet(part: string | undefined): boolean {
  return part !== undefined && /^\d{1,3}$/.test(part) && Number(part) <= 255
}

function ipSubnet(ip: string): string {
  // IPv4 -> first 3 octets (/24).
  if (ip.includes('.')) {
    const octets = ip.split('.')
    // A dual-stack socket reports an IPv4 client as `::ffff:192.0.2.1`, so the first field may carry
    // a v6 prefix. Only the octet after the last colon has to be a number for the /24 to mean
    // anything; the shape is otherwise left exactly as it was, so stored fingerprints still match.
    const head = octets[0]?.slice((octets[0]?.lastIndexOf(':') ?? -1) + 1)
    if (octets.length !== 4 || !isOctet(head) || !octets.slice(1).every(isOctet)) return UNPARSED
    // Normalised numerically, or `203.000.113.009` and `203.0.113.9` hash differently and a proxy
    // that zero-pads where the origin does not re-flags a device the identity already used.
    return `${[head, octets[1], octets[2]].map(Number).join('.')}.0`
  }
  // IPv6 /48; expand `::` first or distinct prefixes collapse to one key.
  const expanded = expandIpv6(ip)
  // SECURITY: junk used to be hashed as-is, so two different unparseable strings were two different
  // devices - a way to mint a `new-device` signal on demand wherever the ip comes from a header.
  if (expanded === null) return UNPARSED
  return `${expanded.split(':').slice(0, 3).join(':')}::`
}

/** Expand a compressed IPv6 (`::1`) to its 8-hextet padded form; null when it is not one. */
function expandIpv6(addr: string): string | null {
  const idx = addr.indexOf('::')
  const parts =
    idx === -1
      ? addr.split(':')
      : (() => {
          const head = addr.slice(0, idx)
          const tail = addr.slice(idx + 2)
          const headParts = head ? head.split(':') : []
          const tailParts = tail ? tail.split(':') : []
          const missing = 8 - headParts.length - tailParts.length
          if (missing < 0) return addr.split(':')
          return [...headParts, ...new Array(missing).fill('0'), ...tailParts]
        })()
  if (parts.length !== 8) return null
  if (!parts.every((h) => /^[0-9a-f]{1,4}$/i.test(h))) return null
  return parts.map((h) => h.padStart(4, '0').toLowerCase()).join(':')
}

/**
 * Build a `new-device` anomaly detector. On first sight of an
 * (identity, fingerprint) pair the detector emits a single signal
 * with the configured score; subsequent sightings emit nothing.
 */
export function deviceFingerprintDetector(cfg: AuthDeviceFingerprint.Cfg): Anomaly.Detector {
  const score = cfg.score ?? 0.7
  if (!Number.isFinite(score) || score < 0 || score > 1) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `deviceFingerprintDetector: score must be a finite number in [0, 1] (got ${score})`,
    })
  }
  const compose = cfg.compose
    ? cfg.compose
    : (req: Anomaly.RequestSnapshot): string | null => {
        if (!cfg.authSha256) return null
        return defaultCompose(req, cfg.authSha256)
      }

  return {
    id: 'new-device',
    async evaluate({ identity, req }): Promise<Anomaly.Signal[]> {
      const fp = compose(req)
      if (!fp) return []
      const known = await cfg.store.checkAndRemember(identity.id, fp)
      if (known) return []
      // The raw ip and user agent are deliberately not here. The `suspicious` event is persisted
      // wherever the bus is, and the fingerprint already identifies the device: carrying the
      // address and the header verbatim only spreads them to every sink that reads the event.
      return [{ evidence: { fingerprint: fp }, kind: 'new-device', score }]
    },
  }
}

export namespace AuthDeviceFingerprint {
  export interface Cfg {
    /**
     * Persistence backing. Memory impl in tests; Redis impl in prod.
     * Required.
     */
    store: AuthDeviceFingerprint.IStore
    /**
     * Score emitted on first sight. Default 0.7 (high but below the
     * default suspicious threshold of 0.8 so it does not auto-step-up
     * - apps tune up when they want stricter behavior).
     */
    score?: number
    /**
     * Fingerprint composer override. Default hashes `${ua}|${ipSubnet}`
     * via the bound crypto helper. Custom composers can add accept-
     * language, screen size (from a beacon), etc.
     */
    compose?: (req: Anomaly.RequestSnapshot) => string | null
    /** Hashing helper (authSha256). Required when relying on default compose. */
    authSha256?: (s: string) => string
  }

  export interface IStore {
    /**
     * Has this identity been seen with `fingerprint` before? Returns
     * true on a known device; false on a brand-new one. Implementations
     * must check + insert atomically (concurrent first-sights from the
     * same device should resolve to "known" for all but the first).
     */
    checkAndRemember(identityId: string, fingerprint: string): Promise<boolean>
    /**
     * Forget every device for an identity. Used by "sign out of all
     * devices" flows + after a credential reset.
     */
    forgetAll(identityId: string): Promise<void>
    /**
     * Forget one sighting.
     *
     * `checkAndRemember` inserts on first sight whatever the caller decides afterwards, so a
     * sign-in the application denied on a `new-device` signal had already whitelisted that
     * fingerprint and the retry passed unremarked. An application that refuses the attempt calls
     * this with the `fingerprint` from the signal's evidence, and the retry is a new device again.
     */
    forget(identityId: string, fingerprint: string): Promise<void>
  }
}

/** Factory around {@link AuthMemoryDeviceFingerprintStore}, for callers who prefer functions to `new`. */
export function authMemoryDeviceFingerprintStore(): AuthMemoryDeviceFingerprintStore {
  return new AuthMemoryDeviceFingerprintStore()
}
