import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'

/** Signal kinds, the detector contract, and the request snapshot they are scored against. */
export namespace Anomaly {
  /** The kinds the shipped detectors emit. A plugin may name its own; `isValidSignal` checks for a
   *  non-empty string, never against this union. */
  export type Kind =
    | 'impossible-travel'
    | 'new-device'
    | 'high-velocity'
    | 'off-hours'
    | 'concurrent-geo'
    | (string & {})

  /** One thing a detector noticed about a request, and how much it counts. */
  export interface Signal {
    /** What was noticed. Free-form, so two detectors emitting the same kind are scoped apart by
     *  {@link Signal.source} rather than by having to agree on a name. */
    kind: Kind
    /** 0..1; higher = more suspicious. Clamped into that range on intake. */
    score: number
    /** Whatever identifies this sighting to a human reading the audit record. It reaches every sink
     *  subscribed to `suspicious`, so it carries derived values - a fingerprint, a distance - and not
     *  the address or header they were computed from. */
    evidence: Record<string, unknown>
    /** The id of the detector that produced this signal. Set by the facet, not by the detector. */
    source?: string
  }

  /** What the detectors are scored against: one request, as the transport saw it. `callerSnapshot`
   *  in `~/server/generic` builds one from an adapter's `getCaller`. */
  export interface RequestSnapshot {
    /** The peer address, never a forwarded header unless the host has decided it can trust one. */
    ip?: string
    /** The `User-Agent` verbatim. Absent is a value, not a reason to skip:
     *  it lands in `FINGERPRINT_ABSENT` rather than switching the detector off for that caller. */
    userAgent?: string
    /** Where the request came from, if the host resolves that. `readonly` because the facet freezes the
     *  snapshot before any detector sees it. */
    geo?: { readonly country?: string; readonly lat?: number; readonly lon?: number }
    /** When the request happened, ms. A parameter rather than a `Date.now()` inside each detector, so
     *  one request is scored against one instant and a caller can pin it. */
    now: number
  }

  /** The plugin contract. A detector is registered once and called per request. */
  export type Detector = {
    /** Unique across the facet, and what a `reactions` entry is scoped by. `'*'` is reserved. */
    readonly id: string
    /** Answer the signals this request earns, or `[]`. Throwing, overrunning `detectorTimeoutMs` or
     *  returning anything else is logged and skipped - the other detectors still decide. */
    evaluate(ctx: { session: Sessions.Me; identity: Identities.Me; req: Readonly<RequestSnapshot> }): Promise<Signal[]>
  }

  /** What the facet recommends. It refuses nothing itself; `requestSecurity` acts on `'deny'`. */
  export type Decision = 'allow' | 'step-up' | 'deny'

  /** The thresholds and overrides the ladder is walked against. */
  export type Cfg = {
    /** Score at or above which the `suspicious` event fires. Default 0.7. Decides nothing by itself,
     *  so an operator can watch scores they are not ready to act on. */
    threshold: number
    /** Aggregate score at or above which `decide()` returns `'step-up'`. Default 0.7. */
    stepUpAt: number
    /** Aggregate score at or above which `decide()` returns `'deny'`. Default 0.95. */
    denyAt: number
    /**
     * Reaction overrides, nested detector id -> kind -> decision, with `'*'` as the detector meaning
     * "whoever emitted it". An `'allow'` mutes that signal and it leaves the aggregate; a `'step-up'`
     * or `'deny'` forces at least that severity whatever it scored.
     *
     * NOTE: nested, not keyed `detectorId#kind`. Kinds are open, so a detector emitting
     * `kind: 'other#new-device'` would reach the entry written for `other` - the exact claim the
     * scoping exists to make false. A level is not a delimiter.
     */
    reactions?: Record<string, Record<string, Decision>>
    /** How long one detector may take before it is abandoned and its signals dropped, 1000 by default.
     *  A detector hanging on a network call would otherwise hold the request open for ever. */
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
  }
}

/** Configuration for the device-fingerprint detector and the store behind it. */
export namespace AuthDeviceFingerprint {
  /** What `deviceFingerprintDetector` takes. */
  export interface Cfg {
    /** `AuthMemoryDeviceFingerprintStore`, or an implementation of {@link AuthDeviceFingerprint.IStore}
     *  over storage every process shares. */
    store: IStore
    /** Emitted on first sight. Default 0.7, which is exactly `stepUpAt` and `threshold`, and both are
     *  compared with `>=`: on the default ladder a single new device raises `suspicious` and decides
     *  `'step-up'` by itself. Lowering it makes a new device only contribute to an aggregate, but below
     *  0.7 it stops raising the event too. */
    score?: number
    /** Fingerprint composer override; the default hashes `${ua}|${ipSubnet}`. A custom one can fold
     *  in accept-language, screen size from a beacon, and so on. `null` skips the request. */
    compose?: (req: Anomaly.RequestSnapshot) => string | null
    /** `authSha256`, required when relying on the default compose. */
    authSha256?: (s: string) => string
  }

  /** Which devices an identity has been seen on. The detector holds no state of its own. */
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

/** Configuration for the impossible-travel detector. */
export namespace AuthImpossibleTravel {
  /** What `authImpossibleTravelDetector` takes as `config`; both fields have defaults. */
  export interface Cfg {
    /** Max speed (km/h) above which the gap counts as suspicious. Default 900. */
    maxKmPerHour: number
    /** Floor on the interval the speed is computed over, ms, and it must be positive. Default 60s:
     *  sub-minute gaps are usually NAT mobility, and dividing a real distance by one reports a speed the
     *  sampling resolution invented. */
    minElapsedMs: number
  }
}
