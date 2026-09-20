/** Device-fingerprint detector: emit `new-device` on first sight of (identity, ua+ipSubnet). */

import { AuthError } from '~/core/errors'
import type { Anomaly } from './anomaly.types'

/** The reference in-memory store; production wires Redis. */
export class AuthMemoryDeviceFingerprintStore implements AuthDeviceFingerprint.IStore {
  /** Insertion-ordered, so the oldest entry is the first the cap evicts. */
  private readonly _known = new Map<string, Map<string, number>>()
  private readonly _maxPerIdentity: number
  private readonly _ttlMs: number

  /** Bounded both ways *per identity*, since one request per rotated user agent would otherwise grow
   *  that set without bound: entries expire, and the oldest is evicted past `maxPerIdentity`.
   *  NOTE: the outer map grows one entry per identity ever seen and is never swept. Its key is an
   *  authenticated `identity.id`, not anything a request names, so it is bounded by the user base
   *  rather than by traffic - the difference from `MemoryLimiter`, whose keys are request-supplied. */
  constructor(cfg: { maxPerIdentity?: number; ttlMs?: number } = {}) {
    this._maxPerIdentity = cfg.maxPerIdentity ?? MEMORY_MAX_PER_IDENTITY
    this._ttlMs = cfg.ttlMs ?? MEMORY_TTL_MS
    // SECURITY: both bounds are applied as a bare `>`, and every comparison against NaN is false, so a
    // non-finite value does not widen the bound, it removes it -- leaving the unbounded growth the doc
    // above says is prevented. Zero and below fail the other way, remembering nothing, so every request
    // is a first sighting.
    if (!Number.isFinite(this._maxPerIdentity) || this._maxPerIdentity <= 0) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `AuthMemoryDeviceFingerprintStore: maxPerIdentity must be a finite positive number (got ${cfg.maxPerIdentity})`,
      })
    }
    if (!Number.isFinite(this._ttlMs) || this._ttlMs <= 0) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `AuthMemoryDeviceFingerprintStore: ttlMs must be a finite positive number (got ${cfg.ttlMs})`,
      })
    }
  }

  /** Atomic check-and-insert: `true` when the fingerprint was already known, `false` on first sight. */
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

  /** For sign-out-of-all flows, and after a forced credential reset. */
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

/** The bucket a request that declines to identify itself lands in.
 *  SECURITY: never `null` from `defaultCompose`, which would switch the detector off for exactly the
 *  caller who chose to send no User-Agent. One shared bucket instead, so the first such request is a
 *  new device and the rest are the same one. */
const ABSENT = '\u0000absent'
const UNPARSED = '\u0000unparsed'

/** authSha256(`${ua}|${ipSubnet}`); /24 IPv4, /48 IPv6. Roaming-tolerant, ISP-sensitive. */
function defaultCompose(req: Anomaly.RequestSnapshot, authSha256: (s: string) => string): string {
  return authSha256(`${uaKey(req.userAgent?.trim())}|${ipKey(req.ip?.trim())}`)
}

/** The default composer, bound to the hash it needs.
 *  SECURITY: refused at construction, because a composer with nothing to hash with answered `null` for
 *  every request and the detector skipped every one of them. Registered, listed, and silent - and a
 *  detector that is switched off reads exactly like one that finds nothing wrong. */
function defaultComposerFor(authSha256: ((s: string) => string) | undefined): (req: Anomaly.RequestSnapshot) => string {
  if (!authSha256) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'deviceFingerprintDetector: pass authSha256 to use the default composer, or a compose of your own',
    })
  }
  return (req) => defaultCompose(req, authSha256)
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
  // SECURITY: junk hashed as-is made two different unparseable strings two different devices, which is
  // a way to mint a `new-device` signal on demand wherever the ip comes from a header.
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

/** A `new-device` detector: one signal at the configured score on first sight of an
 *  (identity, fingerprint) pair, nothing on later ones. */
export function deviceFingerprintDetector(cfg: AuthDeviceFingerprint.Cfg): Anomaly.Detector {
  const score = cfg.score ?? 0.7
  if (!Number.isFinite(score) || score < 0 || score > 1) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `deviceFingerprintDetector: score must be a finite number in [0, 1] (got ${score})`,
    })
  }
  const compose = cfg.compose ?? defaultComposerFor(cfg.authSha256)

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

/** Configuration for the device-fingerprint detector. */
export namespace AuthDeviceFingerprint {
  export interface Cfg {
    /** The memory implementation in tests, the Redis one in production. */
    store: AuthDeviceFingerprint.IStore
    /** Emitted on first sight. Default 0.7: high, but under the 0.8 suspicious threshold, so it does not
     *  auto-step-up until an app tunes it up. */
    score?: number
    /** Fingerprint composer override; the default hashes `${ua}|${ipSubnet}`. A custom one can fold
     *  in accept-language, screen size from a beacon, and so on. */
    compose?: (req: Anomaly.RequestSnapshot) => string | null
    /** `authSha256`, required when relying on the default compose. */
    authSha256?: (s: string) => string
  }

  export interface IStore {
    /** Whether this identity has been seen with `fingerprint` before. Must check and insert
     *  atomically, so concurrent first sights of one device resolve to "known" for all but the first. */
    checkAndRemember(identityId: string, fingerprint: string): Promise<boolean>
    /** For "sign out of all devices" flows, and after a credential reset. */
    forgetAll(identityId: string): Promise<void>
    /** Forget one sighting. `checkAndRemember` inserts on first sight whatever the caller decides
     *  afterwards, so an application that denies the attempt calls this with the `fingerprint` from the
     *  signal's evidence, or the retry passes unremarked. */
    forget(identityId: string, fingerprint: string): Promise<void>
  }
}

export function authMemoryDeviceFingerprintStore(): AuthMemoryDeviceFingerprintStore {
  return new AuthMemoryDeviceFingerprintStore()
}
