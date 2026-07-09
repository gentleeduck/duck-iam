import type { Identity } from '~/core/identities/identities.types'
import type { Session } from '~/core/sessions/sessions.types'

/**
 * Anomaly-detection contract + the AnomalyFacet's own scoring types —
 * the single `Anomaly` namespace for the anomaly subject.
 */
export namespace Anomaly {
  export type Kind = 'impossible-travel' | 'new-device' | 'high-velocity' | 'off-hours' | 'concurrent-geo'

  export interface Signal {
    kind: Kind
    /** 0..1; higher = more suspicious. */
    score: number
    evidence: Record<string, unknown>
  }

  export interface RequestSnapshot {
    ip?: string
    userAgent?: string
    geo?: { country?: string; lat?: number; lon?: number }
    now: number
  }

  export type Detector = {
    readonly id: string
    evaluate(ctx: { session: Session.Me; identity: Identity.Me; req: RequestSnapshot }): Promise<Signal[]>
  }

  /** Recommended response for the caller after evaluating signals. */
  export type Decision = 'allow' | 'step-up' | 'deny'

  export type Config = {
    /** Score threshold above which the `suspicious` event fires. Default 0.7. */
    threshold: number
    /** Aggregate score at or above which `decide()` returns `'step-up'`. Default 0.7. */
    stepUpAt: number
    /** Aggregate score at or above which `decide()` returns `'deny'`. Default 0.95. */
    denyAt: number
    /**
     * Per-signal-kind reaction overrides. Useful when a single signal
     * kind (e.g. `impossible-travel`) should always force step-up
     * regardless of the aggregate score. Highest-severity reaction
     * across present signals wins.
     */
    reactions?: Partial<Record<Kind, Decision>>
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
