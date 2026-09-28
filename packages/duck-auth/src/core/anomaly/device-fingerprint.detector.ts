/** Device-fingerprint detector: emit `new-device` on first sight of (identity, ua+ipSubnet). */

import { AuthError } from '~/core/errors'
import {
  FINGERPRINT_ABSENT,
  FINGERPRINT_IP_MAX_LENGTH,
  FINGERPRINT_MAX_PER_IDENTITY,
  FINGERPRINT_SCORE_DEFAULT,
  FINGERPRINT_TTL_DEFAULT_MS,
  FINGERPRINT_UA_MAX_LENGTH,
  FINGERPRINT_UNPARSED,
} from './anomaly.constants'
import type { Anomaly, AuthDeviceFingerprint } from './anomaly.types'

/** The store this package ships. Process-local, so a deployment running more than one process sees a
 *  first sighting per process: implement {@link AuthDeviceFingerprint.IStore} over shared storage there. */
export class AuthMemoryDeviceFingerprintStore implements AuthDeviceFingerprint.IStore {
  /** Least-recently-seen first, so that is what the cap evicts. */
  private readonly _known = new Map<string, Map<string, number>>()
  private readonly _maxPerIdentity: number
  private readonly _ttlMs: number

  /** At most `maxPerIdentity` devices per identity, each known for `ttlMs` after its last recorded sighting.
   *  NOTE: the outer map holds one entry per identity ever seen and is never swept - bounded by the user
   *  base, not by traffic. */
  constructor(cfg: { maxPerIdentity?: number; ttlMs?: number } = {}) {
    this._maxPerIdentity = cfg.maxPerIdentity ?? FINGERPRINT_MAX_PER_IDENTITY
    this._ttlMs = cfg.ttlMs ?? FINGERPRINT_TTL_DEFAULT_MS
    // SECURITY: both are compared with a bare `>`, so NaN removes the bound rather than widening it; zero
    // or below remembers nothing, and every request is a first sighting.
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

  /** Whether the fingerprint is known and inside the TTL. */
  async has(identityId: string, fingerprint: string): Promise<boolean> {
    const at = this._known.get(identityId)?.get(fingerprint)
    return at !== undefined && Date.now() - at <= this._ttlMs
  }

  /** Remember a sighting as the most recent, evicting the least recently seen past the cap. */
  async remember(identityId: string, fingerprint: string): Promise<void> {
    let seen = this._known.get(identityId)
    if (!seen) {
      seen = new Map()
      this._known.set(identityId, seen)
    }
    // Deleted, then set: `Map.set` on an existing key keeps its old position, and eviction is by position.
    seen.delete(fingerprint)
    seen.set(fingerprint, Date.now())
    for (const oldest of seen.keys()) {
      if (seen.size <= this._maxPerIdentity) break
      seen.delete(oldest)
    }
  }

  /** See {@link AuthDeviceFingerprint.IStore.forgetAll}. */
  async forgetAll(identityId: string): Promise<void> {
    this._known.delete(identityId)
  }

  /** Undo one sighting. See {@link AuthDeviceFingerprint.IStore.forget}. */
  async forget(identityId: string, fingerprint: string): Promise<void> {
    this._known.get(identityId)?.delete(fingerprint)
  }
}

/** `sha256(ua | ipSubnet)`, /24 for IPv4 and /48 for IPv6: roaming-tolerant, ISP-sensitive.
 *  NOTE: the output is stored, so changing its format makes every remembered device new again. */
function defaultCompose(req: Anomaly.RequestSnapshot, authSha256: (s: string) => string): string {
  const ua = req.userAgent?.trim().slice(0, FINGERPRINT_UA_MAX_LENGTH) || FINGERPRINT_ABSENT
  return authSha256(`${ua}|${ipSubnet(req.ip?.trim())}`)
}

/** A decimal 0-255, the only thing a /24 can be built out of. */
function isOctet(part: string): boolean {
  return /^\d{1,3}$/.test(part) && Number(part) <= 255
}

/** The address reduced to the network it came from: /24 for IPv4, /48 for IPv6. */
function ipSubnet(ip: string | undefined): string {
  if (!ip) return FINGERPRINT_ABSENT
  if (ip.length > FINGERPRINT_IP_MAX_LENGTH) return FINGERPRINT_UNPARSED
  if (ip.includes('.')) {
    // A dual-stack socket reports IPv4 as `::ffff:192.0.2.1`: the address is what follows the last colon.
    const octets = ip.slice(ip.lastIndexOf(':', ip.indexOf('.')) + 1).split('.')
    if (octets.length !== 4 || !octets.every(isOctet)) return FINGERPRINT_UNPARSED
    // Numeric, so a zero-padded `203.000.113.009` is the same network as `203.0.113.9`.
    return `${octets.slice(0, 3).map(Number).join('.')}.0`
  }
  // IPv6 /48; expand `::` first or distinct prefixes collapse to one key.
  const expanded = expandIpv6(ip)
  if (expanded === null) return FINGERPRINT_UNPARSED
  return `${expanded.split(':').slice(0, 3).join(':')}::`
}

/** Expand a compressed IPv6 (`::1`) to its 8-hextet padded form; null when it is not one. */
function expandIpv6(addr: string): string | null {
  const [head, tail, ...more] = addr.split('::')
  const groups = (part: string | undefined): string[] => (part ? part.split(':') : [])
  // `::` appears at most once, and stands for as many zero groups as bring the address to eight.
  const zeros = tail === undefined ? 0 : 8 - groups(head).length - groups(tail).length
  if (more.length > 0 || zeros < 0) return null
  const parts = [...groups(head), ...Array<string>(zeros).fill('0'), ...groups(tail)]
  if (parts.length !== 8 || !parts.every((h) => /^[0-9a-f]{1,4}$/i.test(h))) return null
  return parts.map((h) => h.padStart(4, '0').toLowerCase()).join(':')
}

/** A `new-device` detector: one signal at the configured score on first sight of an
 *  (identity, fingerprint) pair, nothing on later ones. */
export function deviceFingerprintDetector(cfg: AuthDeviceFingerprint.Cfg): Anomaly.Detector {
  const score = cfg.score ?? FINGERPRINT_SCORE_DEFAULT
  if (!Number.isFinite(score) || score < 0 || score > 1) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `deviceFingerprintDetector: score must be a finite number in [0, 1] (got ${score})`,
    })
  }
  if (typeof cfg.store?.has !== 'function' || typeof cfg.store.remember !== 'function') {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'deviceFingerprintDetector: store must implement AuthDeviceFingerprint.IStore',
    })
  }
  const { authSha256 } = cfg
  const compose = cfg.compose ?? (authSha256 && ((req: Anomaly.RequestSnapshot) => defaultCompose(req, authSha256)))
  // SECURITY: refused - a detector with nothing to fingerprint would skip every request, silently.
  if (!compose) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'deviceFingerprintDetector: pass authSha256 to use the default composer, or a compose of your own',
    })
  }

  return {
    id: 'new-device',
    async evaluate({ identity, req }): Promise<Anomaly.Signal[]> {
      const fp = compose(req)
      if (typeof fp !== 'string' || fp.length === 0) return []
      if (await cfg.store.has(identity.id, fp)) return []
      // Not the ip or the user agent: evidence reaches every `suspicious` sink.
      return [{ evidence: { fingerprint: fp }, kind: 'new-device', score }]
    },
    // SECURITY: after the verdict, not while scoring - remembered then, a denied device was a known one
    // on the retry, and on a request racing the first.
    async record({ identity, req }, decision): Promise<void> {
      if (decision === 'deny') return
      const fp = compose(req)
      if (typeof fp === 'string' && fp.length > 0) await cfg.store.remember(identity.id, fp)
    },
  }
}

/** {@link AuthMemoryDeviceFingerprintStore}, by default 50 devices per identity and a 90-day TTL. */
export function authMemoryDeviceFingerprintStore(
  ...args: ConstructorParameters<typeof AuthMemoryDeviceFingerprintStore>
): AuthMemoryDeviceFingerprintStore {
  return new AuthMemoryDeviceFingerprintStore(...args)
}
