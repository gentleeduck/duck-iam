/**
 * Device-fingerprint anomaly detector. Emits a `new-device` signal
 * the first time an identity is seen with a particular UA + IP
 * subnet + (optional) accept-language tuple.
 *
 * Why not the full Session.fingerprint? Session-level fingerprint is
 * for hijack detection within a single session; this detector tracks
 * the cross-session set of devices an identity has used so a NEW
 * device can prompt step-up MFA.
 */

import type { Anomaly } from '../types/anomaly'

/**
 * Reference in-memory `DeviceFingerprintStore`. Single-process; tests
 * + dev use this. Production wires Redis-backed implementation.
 */
export class MemoryDeviceFingerprintStore implements DeviceFingerprint.IStore {
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

/**
 * Default fingerprint composer: sha-256 of `${ua}|${ipSubnet}` where
 * the IP subnet is the /24 (IPv4) or /48 (IPv6) prefix. Coarse on
 * purpose; we want roaming inside a household / coffee shop to not
 * flip the signal, but a different country / ISP to flip it.
 */
function defaultCompose(req: Anomaly.RequestSnapshot, sha256: (s: string) => string): string | null {
  const ua = req.userAgent?.trim()
  const ip = req.ip
  if (!ua || !ip) return null
  return sha256(`${ua}|${ipSubnet(ip)}`)
}

function ipSubnet(ip: string): string {
  // IPv4 -> first 3 octets (/24).
  if (ip.includes('.')) {
    return `${ip.split('.').slice(0, 3).join('.')}.0`
  }
  // IPv6 /48; expand `::` first or distinct prefixes collapse to one key.
  return `${expandIpv6(ip).split(':').slice(0, 3).join(':')}::`
}

/** Expand a compressed IPv6 address (`::1`, `2001:db8::1`, etc) to its
 * canonical 8-hextet form, with each hextet zero-padded to 4 chars.
 * Returns the input unchanged when expansion fails (legacy IPv4-mapped
 * notations etc) - the consumer hashes the result so a partial expand
 * still groups consistently. */
function expandIpv6(addr: string): string {
  const idx = addr.indexOf('::')
  const parts =
    idx === -1
      ? addr.split(':')
      : (() => {
          // Cast-free split-on-first-occurrence; slice is always `string`.
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
export function deviceFingerprintDetector(cfg: DeviceFingerprint.IConfig): Anomaly.IDetector {
  const score = cfg.score ?? 0.7
  // Reject NaN/Infinity score; NaN > threshold == false (permissive bypass).
  if (!Number.isFinite(score) || score < 0 || score > 1) {
    throw new Error(`deviceFingerprintDetector: score must be a finite number in [0, 1] (got ${score})`)
  }
  const compose = cfg.compose
    ? cfg.compose
    : (req: Anomaly.RequestSnapshot): string | null => {
        if (!cfg.sha256) return null
        return defaultCompose(req, cfg.sha256)
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

/**
 * Namespace merge for the new-device detector exports.
 */
export namespace DeviceFingerprint {
  export interface IConfig {
    /**
     * Persistence backing. Memory impl in tests; Redis impl in prod.
     * Required.
     */
    store: DeviceFingerprint.IStore
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
    /** Hashing helper (sha256). Required when relying on default compose. */
    sha256?: (s: string) => string
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
