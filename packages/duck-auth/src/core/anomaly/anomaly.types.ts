import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'

/**
 * Anomaly-detection contract + the AnomalyFacet's own scoring types —
 * the single `Anomaly` namespace for the anomaly subject.
 */
export namespace Anomaly {
  export type Kind = 'impossible-travel' | 'new-device' | 'high-velocity' | 'off-hours' | 'concurrent-geo'

  export interface Signal {
    /** A plugin may name a kind outside the union; `source` says who claimed it. */
    kind: Kind
    /** 0..1; higher = more suspicious. Clamped into that range on intake. */
    score: number
    evidence: Record<string, unknown>
    /** The id of the detector that produced this signal. Set by the facet, not by the detector. */
    source?: string
  }

  export interface RequestSnapshot {
    ip?: string
    userAgent?: string
    geo?: { country?: string; lat?: number; lon?: number }
    now: number
  }

  export type Detector = {
    readonly id: string
    evaluate(ctx: { session: Sessions.Me; identity: Identities.Me; req: Readonly<RequestSnapshot> }): Promise<Signal[]>
  }

  /** Recommended response for the caller after evaluating signals. */
  export type Decision = 'allow' | 'step-up' | 'deny'

  export type Cfg = {
    /** Score threshold above which the `suspicious` event fires. Default 0.7. */
    threshold: number
    /** Aggregate score at or above which `decide()` returns `'step-up'`. Default 0.7. */
    stepUpAt: number
    /** Aggregate score at or above which `decide()` returns `'deny'`. Default 0.95. */
    denyAt: number
    /**
     * Reaction overrides, keyed by signal kind or by `detectorId#kind`. The scoped form wins over
     * the bare one, which is how an operator stops a plugin claiming an override written for a
     * different detector: `isValidSignal` accepts kinds outside the union so plugins can extend it,
     * and a free-string kind would otherwise choose which configured reaction applies to it.
     *
     * `deny` and `step-up` raise the outcome whatever the score is. `allow` mutes that signal: its
     * score leaves the aggregate entirely, so a noisy detector can be held back without also
     * holding back the detectors that ran beside it.
     */
    reactions?: Record<string, Decision>
    /**
     * How long one detector may take before it is abandoned and its signals dropped. Default 1000.
     * A detector that hangs on a network call would otherwise hold the request open for ever.
     */
    detectorTimeoutMs: number
  }

  export type Result = {
    /** Sum of all signal scores. */
    score: number
    /** Individual detector outputs that contributed to the score. */
    signals: Signal[]
    /** Recommended response. Callers may override but should log when they do. */
    decision: Decision
  }
}
