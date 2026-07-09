import type { Identity } from '../identities/identities.types'
import type { Session } from '../sessions/sessions.types'
import type { Anomaly, Events } from '../types/provider'

export namespace AnomalyFacet {
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
    reactions?: Partial<Record<Anomaly.Kind, Decision>>
  }

  export type Result = {
    /** Sum of all signal scores. */
    score: number
    /** Individual detector outputs that contributed to the score. */
    signals: Anomaly.Signal[]
    /** Recommended response. Callers may override but should log when they do. */
    decision: Decision
  }
}

/** Conservative defaults. Step-up at 0.7; deny at 0.95. */
export const DEFAULT_ANOMALY_CONFIG: AnomalyFacet.Config = {
  threshold: 0.7,
  stepUpAt: 0.7,
  denyAt: 0.95,
}

/** Sum signal scores, treating non-finite values as 0. */
function sumScores(signals: Anomaly.Signal[]): number {
  let acc = 0
  for (const s of signals) {
    if (Number.isFinite(s.score)) acc += s.score
  }
  return acc
}

/**
 * structural type-guard for Anomaly.Signal. A signal from a
 * misbehaving detector that lacks the right shape (e.g. `null`,
 * `{}`, `{ kind: 42 }`) would otherwise reach `decide()` and crash
 * its `Number.isFinite(s.score)` access - see {@link AnomalyFacet.evaluate}
 * for the fail-open chain. This guard skips them before they hit
 * `signals.push`.
 */
function isValidSignal(raw: unknown): raw is Anomaly.Signal {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return false
  // typeof 'string' for kind is the contract; we intentionally do
  // NOT restrict to the union (plugins may define new kinds).
  if (!('kind' in raw) || typeof raw.kind !== 'string' || raw.kind.length === 0) return false
  if (!('score' in raw) || typeof raw.score !== 'number') return false
  // `evidence` is required by the type but defensive: missing is OK
  // (treated as {}). The signal is still useful.
  return true
}

/**
 * Anomaly facet. Apps register one or more detectors; the facet evaluates
 * them on a per-request basis (typically after `resolveSession`).
 *
 * The aggregator runs every registered detector, sums signal scores, and
 * returns a recommended `IDecision` so callers can branch on a single
 * field rather than re-implementing the threshold ladder at every call
 * site. The `decide()` helper exposes the same logic standalone for
 * tests / custom pipelines.
 */
export class AnomalyFacet {
  private readonly _detectors: Anomaly.Detector[] = []
  private readonly _cfg: AnomalyFacet.Config

  constructor(
    private readonly _events: Events.IBus,
    cfg: Partial<AnomalyFacet.Config> = {},
  ) {
    this._cfg = { ...DEFAULT_ANOMALY_CONFIG, ...cfg }
  }

  /** Register a detector. Order does not affect aggregate score. */
  register(detector: Anomaly.Detector): void {
    this._detectors.push(detector)
  }

  /** Remove a previously-registered detector by id. No-op if not found. */
  unregister(id: string): void {
    const idx = this._detectors.findIndex((d) => d.id === id)
    if (idx >= 0) this._detectors.splice(idx, 1)
  }

  /** Currently registered detector ids; UI / diagnostics. */
  list(): string[] {
    return this._detectors.map((d) => d.id)
  }

  /**
   * Run every detector + return the aggregate + recommended decision.
   *
   * Emits `suspicious` when the summed score crosses `threshold`; the
   * caller still picks the response - the decision is a recommendation,
   * not an enforcement. Detector exceptions are caught + logged so a
   * misbehaving plugin can never lock users out of authn.
   */
  async evaluate(input: {
    session: Session.Me
    identity: Identity.Me
    req: Anomaly.RequestSnapshot
  }): Promise<AnomalyFacet.Result> {
    const signals: Anomaly.Signal[] = []
    for (const d of this._detectors) {
      try {
        const out = await d.evaluate(input)
        // Validate every signal individually; a malformed return value
        // would otherwise crash decide() and silently drop the result.
        if (!Array.isArray(out)) {
          console.error(`[@gentleduck/auth] anomaly detector "${d.id}" returned non-array; skipping`)
          continue
        }
        for (const raw of out) {
          if (isValidSignal(raw)) signals.push(raw)
          else console.error(`[@gentleduck/auth] anomaly detector "${d.id}" returned invalid signal; skipping`)
        }
      } catch (err) {
        // Detector bug must not break authn flow; log + skip.
        console.error(`[@gentleduck/auth] anomaly detector "${d.id}" threw:`, err)
      }
    }
    const score = sumScores(signals)
    if (score >= this._cfg.threshold && signals.length > 0) {
      await this._events.emit('suspicious', {
        ...(input.identity.id && { identityId: input.identity.id }),
        signal: signals.map((s) => s.kind).join('+'),
        score,
        meta: { signals },
      })
    }
    return { score, signals, decision: this.decide(signals) }
  }

  /**
   * Map a signal set to a recommended decision. Standalone so callers
   * can re-decide on cached signals or test the ladder without invoking
   * detectors.
   *
   * Decision order (any match short-circuits):
   *   1. `denyAt` crossed -> 'deny'
   *   2. Per-signal-kind override in `reactions` (highest severity wins:
   *      deny > step-up > allow)
   *   3. `stepUpAt` crossed -> 'step-up'
   *   4. Otherwise -> 'allow'
   */
  decide(signals: Anomaly.Signal[]): AnomalyFacet.Decision {
    // Non-finite score collapses every comparison and falls through to allow.
    if (signals.some((s) => !Number.isFinite(s.score))) return 'deny'
    const score = sumScores(signals)
    if (score >= this._cfg.denyAt) return 'deny'
    if (this._cfg.reactions) {
      let kindDecision: AnomalyFacet.Decision = 'allow'
      const severity: Record<AnomalyFacet.Decision, number> = { allow: 0, 'step-up': 1, deny: 2 }
      for (const s of signals) {
        const r = this._cfg.reactions[s.kind]
        if (!r) continue
        if (severity[r] > severity[kindDecision]) kindDecision = r
      }
      if (severity[kindDecision] > 0) return kindDecision
    }
    if (score >= this._cfg.stepUpAt) return 'step-up'
    return 'allow'
  }
}
