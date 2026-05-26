/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { Anomaly } from '../types/anomaly'
import type { Events } from '../types/events'
import type { Identity } from '../types/identity'
import type { Session } from '../types/session'

/**
 * Anomaly aggregator. Runs every registered detector against the supplied
 * (session, identity, request) snapshot, sums the scores, and emits a
 * `suspicious` event when the aggregate crosses the configured threshold.
 *
 * Detectors run sequentially; a detector throwing does not abort the
 * batch (logged + skipped). Cost is bounded by the number of detectors
 * registered, so apps with strict latency budgets pick the detectors
 * they want and skip the rest.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface AnomalyFacetConfig {
  /** Score threshold above which we emit `suspicious`. Default 0.7. */
  threshold: number
}

/** Conservative defaults. */
export const DEFAULT_ANOMALY_CONFIG: AnomalyFacetConfig = {
  threshold: 0.7,
}

/**
 * Anomaly facet. Apps register one or more detectors; AuthFacet evaluates
 * them on a per-request basis (typically from the resolveSession path).
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class AnomalyFacet {
  private readonly _detectors: Anomaly.IDetector[] = []
  private readonly _cfg: AnomalyFacetConfig

  constructor(
    private readonly _events: Events.IBus,
    cfg: AnomalyFacetConfig = DEFAULT_ANOMALY_CONFIG,
  ) {
    this._cfg = cfg
  }

  /** Register a detector. Order does not affect aggregate score. */
  register(detector: Anomaly.IDetector): void {
    this._detectors.push(detector)
  }

  /** Currently registered detector ids; UI / diagnostics. */
  list(): string[] {
    return this._detectors.map((d) => d.id)
  }

  /**
   * Run every detector + return the aggregate. Emits `suspicious` when
   * the summed score exceeds threshold; the caller can additionally
   * apply HijackPolicy-style reactions on the returned signals.
   */
  async evaluate(input: {
    session: Session.ISession
    identity: Identity.IIdentity
    req: Anomaly.RequestSnapshot
  }): Promise<{ score: number; signals: Anomaly.Signal[] }> {
    const signals: Anomaly.Signal[] = []
    for (const d of this._detectors) {
      try {
        const out = await d.evaluate(input)
        signals.push(...out)
      } catch (err) {
        // Detector bug must not break authn flow; log + skip.
        // eslint-disable-next-line no-console
        console.error(`[@gentleduck/auth] anomaly detector "${d.id}" threw:`, err)
      }
    }
    const score = signals.reduce((acc, s) => acc + s.score, 0)
    if (score >= this._cfg.threshold && signals.length > 0) {
      await this._events.emit('suspicious', {
        ...(input.identity.id && { identityId: input.identity.id }),
        signal: signals.map((s) => s.kind).join('+'),
        score,
        meta: { signals },
      })
    }
    return { score, signals }
  }
}

/**
 * Namespace merge for AnomalyFacet. Co-locates the config + output shapes
 * alongside the class.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace AnomalyFacet {
  /** Alias for the flat `AnomalyFacetConfig` type. */
  export type IConfig = AnomalyFacetConfig
}
