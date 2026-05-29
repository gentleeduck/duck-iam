/**
 * @packageDocumentation
 * Device-fingerprint anomaly detector. Emits a `new-device` signal
 * the first time an identity is seen with a particular UA + IP
 * subnet + (optional) accept-language tuple.
 *
 * Why not the full Session.fingerprint? Session-level fingerprint is
 * for hijack detection within a single session; this detector tracks
 * the cross-session set of devices an identity has used so a NEW
 * device can prompt step-up MFA.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { Anomaly } from '../types/anomaly'

/**
 * Persistence contract for known-device fingerprints. Apps wire to
 * Redis SADD/SMEMBERS or a SQL table. Memory implementation ships in-
 * tree for tests / single-process apps.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface DeviceFingerprintStore {
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

/**
 * Reference in-memory `DeviceFingerprintStore`. Single-process; tests
 * + dev use this. Production wires Redis-backed implementation.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class MemoryDeviceFingerprintStore implements DeviceFingerprintStore {
  private readonly _known = new Map<string, Set<string>>()

  /**
   * Atomic check-and-insert. Returns true when the fingerprint was
   * already known; false on first sight.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
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
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async forgetAll(identityId: string): Promise<void> {
    this._known.delete(identityId)
  }
}

/**
 * Config knobs for `deviceFingerprintDetector`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface DeviceFingerprintConfig {
  /**
   * Persistence backing. Memory impl in tests; Redis impl in prod.
   * Required.
   */
  store: DeviceFingerprintStore
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

/**
 * Default fingerprint composer: sha-256 of `${ua}|${ipSubnet}` where
 * the IP subnet is the /24 (IPv4) or /48 (IPv6) prefix. Coarse on
 * purpose; we want roaming inside a household / coffee shop to not
 * flip the signal, but a different country / ISP to flip it.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
function defaultCompose(req: Anomaly.RequestSnapshot, sha256: (s: string) => string): string | null {
  const ua = req.userAgent?.trim()
  const ip = req.ip
  if (!ua || !ip) return null
  return sha256(`${ua}|${ipSubnet(ip)}`)
}

function ipSubnet(ip: string): string {
  // IPv4 -> first 3 octets; IPv6 -> first 3 hextets.
  if (ip.includes('.')) {
    return ip.split('.').slice(0, 3).join('.') + '.0'
  }
  return ip.split(':').slice(0, 3).join(':') + '::'
}

/**
 * Build a `new-device` anomaly detector. On first sight of an
 * (identity, fingerprint) pair the detector emits a single signal
 * with the configured score; subsequent sightings emit nothing.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function deviceFingerprintDetector(cfg: DeviceFingerprintConfig): Anomaly.IDetector {
  const score = cfg.score ?? 0.7
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
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace DeviceFingerprint {
  /** Alias for `DeviceFingerprintConfig`. */
  export type IConfig = DeviceFingerprintConfig
  /** Alias for `DeviceFingerprintStore`. */
  export type IStore = DeviceFingerprintStore
}
