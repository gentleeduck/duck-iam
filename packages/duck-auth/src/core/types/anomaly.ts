import type { AuthIdentity } from './identity'
import type { AuthSession } from './session'

/**
 * AuthAnomaly-detection adapter contract. Each detector evaluates a request
 * + session and returns zero or more signals. Apps register one or more
 * detectors; AuthEngine aggregates the scores and emits `suspicious` when
 * thresholds trip
 */
export namespace AuthAnomaly {
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

  export interface IDetector {
    readonly id: string
    evaluate(ctx: { session: AuthSession.ISession; identity: AuthIdentity.IIdentity; req: RequestSnapshot }): Promise<Signal[]>
  }
}
