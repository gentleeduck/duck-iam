/** Device-fingerprint detector: emit `new-device` on first sight of (identity, ua+ipSubnet). */

import type { Anomaly } from './anomaly.types'

/** Reference in-memory device-fingerprint store; production wires Redis. */
export class AuthMemoryDeviceFingerprintStore implements AuthDeviceFingerprint.IStore {
  private readonly _known = new Map<string, Set<string>>()

  /**
   * Atomic check-and-insert. Returns true when the fingerprint was
   * already known; false on first sight.
   */
  async checkAndRemember(identityId: string, fingerprint: string): Promise<boolean> {
    let set = this._known.get(identityId)
    if (!set) {
      set = new Set()
      this._known.set(identityId, set)
    }
    if (set.has(fingerprint)) return true
    set.add(fingerprint)
    return false
  }

  /**
   * Wipe every fingerprint for an identity. Used by sign-out-of-all
   * flows + after a forced credential reset.
   */
  async forgetAll(identityId: string): Promise<void> {
    this._known.delete(identityId)
  }
}

/** authSha256(`${ua}|${ipSubnet}`); /24 IPv4, /48 IPv6. Roaming-tolerant, ISP-sensitive. */
function defaultCompose(req: Anomaly.RequestSnapshot, authSha256: (s: string) => string): string | null {
  const ua = req.userAgent?.trim()
  const ip = req.ip
  if (!ua || !ip) return null
  if (ua.length > 1024 || ip.length > 64) return null
  return authSha256(`${ua}|${ipSubnet(ip)}`)
}

function ipSubnet(ip: string): string {
  // IPv4 -> first 3 octets (/24).
  if (ip.includes('.')) {
    return `${ip.split('.').slice(0, 3).join('.')}.0`
  }
  // IPv6 /48; expand `::` first or distinct prefixes collapse to one key.
  return `${expandIpv6(ip).split(':').slice(0, 3).join(':')}::`
}

/** Expand a compressed IPv6 (`::1`) to its 8-hextet padded form; returns input on parse failure. */
function expandIpv6(addr: string): string {
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
  if (parts.length !== 8) return addr
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
    throw new Error(`deviceFingerprintDetector: score must be a finite number in [0, 1] (got ${score})`)
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
      return [
        {
          kind: 'new-device',
          score,
          evidence: {
            fingerprint: fp,
            ip: req.ip ?? null,
            userAgent: req.userAgent ?? null,
          },
        },
      ]
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
  }
}

/** Factory around {@link AuthMemoryDeviceFingerprintStore}, for callers who prefer functions to `new`. */
export function authMemoryDeviceFingerprintStore(): AuthMemoryDeviceFingerprintStore {
  return new AuthMemoryDeviceFingerprintStore()
}
