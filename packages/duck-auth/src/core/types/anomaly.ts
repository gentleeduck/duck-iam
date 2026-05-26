/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { Identity } from './identity'
import type { Session } from './session'

/**
 * Anomaly-detection adapter contract. Each detector evaluates a request
 * + session and returns zero or more signals. Apps register one or more
 * detectors; AuthRoot aggregates the scores and emits `suspicious` when
 * thresholds trip. DESIGN section T2.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
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

  export interface IDetector {
    readonly id: string
    evaluate(ctx: { session: Session.ISession; identity: Identity.IIdentity; req: RequestSnapshot }): Promise<Signal[]>
  }
}
