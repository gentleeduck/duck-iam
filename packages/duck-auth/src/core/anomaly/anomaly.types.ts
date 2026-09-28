import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'

/** Signal kinds, the detector contract, and the request snapshot they are scored against. */
export namespace Anomaly {
  /** The shipped detectors' kinds; a plugin may name any non-empty string. */
  export type Kind = 'impossible-travel' | 'new-device' | (string & {})

  /** One thing a detector noticed about a request, and how much it counts. */
  export interface Signal {
    /** What was noticed. Two detectors may emit the same kind; {@link Signal.source} tells them apart. */
    kind: Kind
    /** 0..1; higher = more suspicious. Clamped into that range on intake. */
    score: number
    /** What a human reading the audit record needs. It reaches every `suspicious` sink, so it carries
     *  derived values - a fingerprint, a distance - never the address, header or position behind them. */
    evidence: Record<string, unknown>
    /** The id of the detector that produced this signal. Set by the facet, not by the detector. */
    source?: string
  }

  /** What the detectors are scored against: one request, as the transport saw it. `requestSecurity`
   *  in `~/server/generic` builds one from an adapter's `getCaller`. */
  export interface RequestSnapshot {
    /** The peer address, never a forwarded header unless the host has decided it can trust one. */
    ip?: string
    /** The `User-Agent`, verbatim. Absent is fingerprinted too, as `FINGERPRINT_ABSENT`. */
    userAgent?: string
    /** Where the request came from, when the host resolves it; it arrives through `getCaller`. */
    geo?: { readonly country?: string; readonly lat?: number; readonly lon?: number }
    /** When the request happened, epoch ms: one instant for every detector, and pinnable by a caller. */
    now: number
  }

  /** What a detector is called with: the resolved session, its identity, and the request. */
  export type Context = { session: Sessions.Me; identity: Identities.Me; req: Readonly<RequestSnapshot> }

  /** The plugin contract. A detector is registered once and called per request. */
  export type Detector = {
    /** Unique across the facet, and what a `reactions` entry is scoped by. `'*'` is reserved. */
    readonly id: string
    /** Answer the signals this request earns, or `[]`. Throwing, overrunning `detectorTimeoutMs` or
     *  returning anything else is logged and skipped - the other detectors still decide. */
    evaluate(ctx: Context): Promise<Signal[]>
    /** Called by {@link Anomaly.Result.admit} once the request is let through, under the same deadline:
     *  what was learned from a refused request belongs to the attacker. Skipped when `evaluate` never
     *  answered; a throw here is logged. */
    record?(ctx: Context, decision: Decision): Promise<void>
  }

  /** What the facet recommends. It refuses nothing itself; `requestSecurity` acts on `'deny'`. */
  export type Decision = 'allow' | 'step-up' | 'deny'

  /** The thresholds and overrides the ladder is walked against. */
  export type Cfg = {
    /** `suspicious` fires for every decision but `'allow'`, and for an `'allow'` scoring at least this.
     *  Default 0.7. Decides nothing. */
    threshold: number
    /** Aggregate score at or above which `decide()` returns `'step-up'`. Default 0.7. */
    stepUpAt: number
    /** Aggregate score at or above which `decide()` returns `'deny'`. Default 0.95. */
    denyAt: number
    /**
     * Overrides by detector id, then kind, with `'*'` for any detector. `'allow'` mutes the signal;
     * `'step-up'` or `'deny'` forces at least that decision whatever it scored.
     * NOTE: nested because kinds are open - a flat `id#kind` key could be forged by a kind holding `#`.
     */
    reactions?: Record<string, Record<string, Decision>>
    /** How long one detector may run before it is abandoned and its signals dropped. Default 1000. */
    detectorTimeoutMs: number
  }

  /** What `evaluate` answers, and what rides along to `onSession` as `resolveSession`'s `anomaly`. */
  export type Result = {
    /** The signals combined noisy-or and saturating at 1, not summed: see `combineScores`. */
    score: number
    /** The signals that contributed to it; one muted by an `'allow'` reaction is not among them. */
    signals: Signal[]
    /** Callers may override it, but should log when they do. */
    decision: Decision
    /** Runs the `record` of each detector that answered, under `decision`. Call it once the request is let
     *  through: `withRequestActor` and `withResolvedActor` do, after `onSession` passes, so a request refused
     *  there teaches the detectors nothing. Never rejects. */
    admit: () => Promise<void>
  }
}

/** Configuration for the device-fingerprint detector and the store behind it. */
export namespace AuthDeviceFingerprint {
  /** What `deviceFingerprintDetector` takes. */
  export interface Cfg {
    /** `AuthMemoryDeviceFingerprintStore`, or an {@link AuthDeviceFingerprint.IStore} over storage every
     *  process shares. */
    store: IStore
    /** Emitted on first sight. Default 0.7 - exactly `stepUpAt`, so on the default ladder a new device
     *  alone steps up. */
    score?: number
    /** Replaces the default `sha256(ua | ipSubnet)`; `null` skips the request. */
    compose?: (req: Anomaly.RequestSnapshot) => string | null
    /** The hash the default `compose` needs - `sha256` from `core`. Required without a `compose`. */
    authSha256?: (s: string) => string
  }

  /** Which devices an identity has been seen on; the detector holds no state of its own. */
  export interface IStore {
    /** Whether this identity was seen on `fingerprint`, within the TTL. */
    has(identityId: string, fingerprint: string): Promise<boolean>
    /** Remember a sighting, or refresh one. Called once the request is let through, never for a `'deny'`. */
    remember(identityId: string, fingerprint: string): Promise<void>
    /** Forget every device of an identity, after "sign out everywhere" or a credential reset. Nothing in
     *  this package calls it. */
    forgetAll(identityId: string): Promise<void>
    /** Forget one sighting.
     *  WARN: a `'step-up'` that `onSession` lets through is remembered, so a route that refuses one on
     *  `anomaly.decision` passes the signal's `evidence.fingerprint` here, or the retry passes as a known
     *  device. */
    forget(identityId: string, fingerprint: string): Promise<void>
  }
}

/** Configuration for the impossible-travel detector. */
export namespace AuthImpossibleTravel {
  /** What `authImpossibleTravelDetector` takes as `config`; both fields have defaults. */
  export interface Cfg {
    /** Max speed (km/h) above which the gap counts as suspicious. Default 900. */
    maxKmPerHour: number
    /** Floor on the interval the speed is computed over, ms. Default 60s: a sub-minute gap is sampling
     *  noise, not travel. */
    minElapsedMs: number
  }
}
