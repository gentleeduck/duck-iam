import { AuthError } from '~/core/errors'
import type { Events } from '~/core/events/events.types'
import { isRecord } from '~/core/predicates'
import type { Identities } from '../identities/identities.types'
import type { Sessions } from '../sessions/sessions.types'
import {
  clampScore,
  combineScores,
  DECISION_SEVERITY,
  DEFAULT_ANOMALY_CONFIG,
  DETECTOR_TIMEOUT_MAX_MS,
  REACTION_ANY_DETECTOR,
} from './anomaly.constants'
import type { Anomaly } from './anomaly.types'

/** A `Signal` as a detector returns it: `evidence` may be absent. */
type RawSignal = Omit<Anomaly.Signal, 'evidence'> & { evidence?: Record<string, unknown> }

/** Whether a detector's return value is a usable signal; anything else is logged and skipped. */
function isValidSignal(raw: unknown): raw is RawSignal {
  if (!isRecord(raw)) return false
  // A string, not a member of the union: plugins name their own kinds.
  if (typeof raw.kind !== 'string' || raw.kind.length === 0) return false
  if (typeof raw.score !== 'number') return false
  // Absent reads as `{}`; present, it must be a record, as every `suspicious` sink assumes.
  if (raw.evidence !== undefined && !isRecord(raw.evidence)) return false
  return true
}

/** The detector registry and the ladder: runs every detector against a request, combines their scores
 *  noisy-or and answers one decision. The ladder is on {@link AnomalyFacet.decide}. */
export class AnomalyFacet {
  private readonly _detectors: Anomaly.Detector[] = []
  private readonly _cfg: Anomaly.Cfg

  constructor(
    private readonly _events: Events.IBus,
    cfg: Partial<Anomaly.Cfg> = {},
  ) {
    // Per field, so an explicit `undefined` reads as omitted rather than replacing the default.
    this._cfg = {
      denyAt: cfg.denyAt ?? DEFAULT_ANOMALY_CONFIG.denyAt,
      detectorTimeoutMs: cfg.detectorTimeoutMs ?? DEFAULT_ANOMALY_CONFIG.detectorTimeoutMs,
      reactions: cfg.reactions,
      stepUpAt: cfg.stepUpAt ?? DEFAULT_ANOMALY_CONFIG.stepUpAt,
      threshold: cfg.threshold ?? DEFAULT_ANOMALY_CONFIG.threshold,
    }
    // SECURITY: each of these fails open when wrong - `score >= NaN` is false, and `setTimeout` runs a
    // non-finite or oversized delay at 1ms, abandoning every detector before it answers.
    for (const key of ['threshold', 'stepUpAt', 'denyAt'] as const) {
      if (!Number.isFinite(this._cfg[key]) || this._cfg[key] < 0 || this._cfg[key] > 1) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: `anomalyFacet: ${key} must be a number between 0 and 1 (got ${this._cfg[key]})`,
        })
      }
    }
    const timeout = this._cfg.detectorTimeoutMs
    if (!Number.isFinite(timeout) || timeout < 1 || timeout > DETECTOR_TIMEOUT_MAX_MS) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `anomalyFacet: detectorTimeoutMs must be a number between 1 and ${DETECTOR_TIMEOUT_MAX_MS} (got ${timeout})`,
      })
    }
    // A misspelled decision would compare false against every severity and apply nowhere.
    for (const [detectorId, table] of Object.entries(this._cfg.reactions ?? {})) {
      if (!isRecord(table)) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: `anomalyFacet: reactions['${detectorId}'] must be an object of kind -> decision`,
        })
      }
      for (const [kind, decision] of Object.entries(table)) {
        if (decision !== 'allow' && decision !== 'step-up' && decision !== 'deny') {
          throw new AuthError('AUTH_MISCONFIGURED', {
            detail: `anomalyFacet: reactions['${detectorId}']['${kind}'] must be 'allow', 'step-up' or 'deny' (got ${String(decision)})`,
          })
        }
      }
    }
    // Logged, not refused: stricter rather than weaker, but it leaves the step-up rung dead.
    if (this._cfg.denyAt < this._cfg.stepUpAt) {
      console.error(
        `[@gentleduck/auth] anomaly: denyAt (${this._cfg.denyAt}) is below stepUpAt (${this._cfg.stepUpAt}), so nothing can ever step up`,
      )
    }
  }

  /** Add a detector. A duplicate id is refused, or a module loaded twice would count twice. */
  register(detector: Anomaly.Detector): void {
    if (
      typeof detector?.evaluate !== 'function' ||
      (detector.record !== undefined && typeof detector.record !== 'function') ||
      typeof detector.id !== 'string' ||
      detector.id.length === 0
    ) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail:
          'anomaly detector needs a non-empty string id and an evaluate function, and a record only as a function',
      })
    }
    if (detector.id === REACTION_ANY_DETECTOR) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `anomaly detector id '${REACTION_ANY_DETECTOR}' is reserved for the reactions wildcard`,
      })
    }
    if (this._detectors.some((d) => d.id === detector.id)) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `anomaly detector "${detector.id}" is already registered; unregister it before registering again`,
      })
    }
    this._detectors.push(detector)
  }

  /** Remove a detector by id; `false` when none matched. */
  unregister(id: string): boolean {
    const idx = this._detectors.findIndex((d) => d.id === id)
    if (idx < 0) return false
    this._detectors.splice(idx, 1)
    return true
  }

  /** The registered detector ids, in registration order. */
  list(): string[] {
    return this._detectors.map((d) => d.id)
  }

  /** Runs every detector concurrently under `detectorTimeoutMs`; one that throws or overruns is logged
   *  and skipped, so no plugin can lock users out. */
  async evaluate(input: {
    session: Sessions.Me
    identity: Identities.Me
    req: Anomaly.RequestSnapshot
  }): Promise<Anomaly.Result> {
    // Said, not refused: a non-number `now` turns every time-based detector off for this request.
    if (!Number.isFinite(input.req.now)) {
      console.error('[@gentleduck/auth] anomaly: req.now is not a finite number; time-based detectors cannot score')
    }
    const { geo } = input.req
    // Frozen, geo included, so the first detector registered cannot decide what the rest see.
    const req = Object.freeze({ ...input.req, ...(geo && { geo: Object.freeze({ ...geo }) }) })
    const ctx: Anomaly.Context = { identity: input.identity, req, session: input.session }
    // Copied, so a detector registered mid-request records nothing it never scored.
    const detectors = [...this._detectors]
    const answers = await Promise.all(detectors.map((d) => this._runDetector(d, ctx)))
    const { decision, kept, score } = this._aggregate(answers.flatMap((signals) => signals ?? []))

    if (decision !== 'allow' || (score >= this._cfg.threshold && kept.length > 0)) {
      // SECURITY: logged, not thrown - `resolveSession` drops the whole result on a throw, deny included.
      try {
        await this._events.emit('suspicious', {
          identityId: input.identity.id,
          meta: { decision, signals: kept },
          score,
          signal: kept.map((s) => s.kind).join('+'),
        })
      } catch (err) {
        console.error('[@gentleduck/auth] anomaly could not emit "suspicious":', err)
      }
    }
    return {
      // Not for a detector that threw or overran: a slow store would make a device known that nothing judged.
      admit: async () => {
        await Promise.all(detectors.filter((_, i) => answers[i]).map((d) => this._record(d, ctx, decision)))
      },
      decision,
      score,
      signals: kept,
    }
  }

  /** The detector's usable signals, or `null` when it never answered. */
  private async _runDetector(d: Anomaly.Detector, ctx: Anomaly.Context): Promise<Anomaly.Signal[] | null> {
    try {
      const out = await this._bounded(d, d.evaluate(ctx))
      if (!Array.isArray(out)) {
        console.error(`[@gentleduck/auth] anomaly detector "${d.id}" returned non-array; skipping`)
        return null
      }
      const accepted: Anomaly.Signal[] = []
      for (const raw of out) {
        if (!isValidSignal(raw)) {
          console.error(`[@gentleduck/auth] anomaly detector "${d.id}" returned invalid signal; skipping`)
          continue
        }
        // Stamped here, never taken from the detector: reactions are scoped by it.
        accepted.push({
          ...raw,
          evidence: raw.evidence ?? {},
          score: Number.isFinite(raw.score) ? clampScore(raw.score) : raw.score,
          source: d.id,
        })
      }
      return accepted
    } catch (err) {
      // A detector bug must not break the authn flow: log and skip.
      console.error(`[@gentleduck/auth] anomaly detector "${d.id}" threw:`, err)
      return null
    }
  }

  private async _record(d: Anomaly.Detector, ctx: Anomaly.Context, decision: Anomaly.Decision): Promise<void> {
    if (!d.record) return
    try {
      await this._bounded(d, d.record(ctx, decision))
    } catch (err) {
      // Never rethrown: bookkeeping must not refuse a request the checks let through.
      console.error(`[@gentleduck/auth] anomaly detector "${d.id}" could not record:`, err)
    }
  }

  /** `work`, abandoned once it overruns `detectorTimeoutMs`. */
  private async _bounded<T>(d: Anomaly.Detector, work: Promise<T>): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      return await Promise.race([
        work,
        new Promise<never>((_, reject) => {
          timer = setTimeout(
            () => reject(new Error(`detector "${d.id}" exceeded ${this._cfg.detectorTimeoutMs}ms`)),
            this._cfg.detectorTimeoutMs,
          )
        }),
      ])
    } finally {
      clearTimeout(timer)
    }
  }

  /**
   * The ladder, standalone for re-deciding on signals already held. First match wins:
   *   1. An `allow` reaction mutes that signal; it leaves the aggregate entirely
   *   2. A non-finite score among what remains -> 'deny'
   *   3. `denyAt` crossed -> 'deny'
   *   4. A `deny` or `step-up` reaction on a remaining kind (highest severity wins)
   *   5. `stepUpAt` crossed -> 'step-up'
   *   6. Otherwise -> 'allow'
   */
  decide(signals: Anomaly.Signal[]): Anomaly.Decision {
    return this._aggregate(signals).decision
  }

  private _aggregate(signals: Anomaly.Signal[]): {
    score: number
    decision: Anomaly.Decision
    kept: Anomaly.Signal[]
  } {
    const scored = signals
      .map((signal) => ({ reaction: this._reactionFor(signal), signal }))
      .filter((s) => s.reaction !== 'allow')
    // What the verdict is computed from, and all that is reported: a muted signal leaves both.
    const kept = scored.map((s) => s.signal)
    const finite = scored.filter((s) => Number.isFinite(s.signal.score))
    // SECURITY: clamped again because `decide` takes the caller's signals, and noisy-or over a score
    // above 1 lowers the aggregate as evidence is added.
    const score = combineScores(finite.map((s) => clampScore(s.signal.score)))
    // Explicit: a NaN or an Infinity fails every comparison below and would reach `allow`.
    if (finite.length !== scored.length) return { decision: 'deny', kept, score }
    if (score >= this._cfg.denyAt) return { decision: 'deny', kept, score }
    let forced: Anomaly.Decision = 'allow'
    for (const { reaction } of scored) {
      if (reaction && DECISION_SEVERITY[reaction] > DECISION_SEVERITY[forced]) forced = reaction
    }
    if (forced !== 'allow') return { decision: forced, kept, score }
    if (score >= this._cfg.stepUpAt) return { decision: 'step-up', kept, score }
    return { decision: 'allow', kept, score }
  }

  /** The detector's own table, then `'*'`. `Object.hasOwn` at both levels, so an id or kind spelling a
   *  prototype member matches nothing. */
  private _reactionFor(signal: Anomaly.Signal): Anomaly.Decision | undefined {
    const reactions = this._cfg.reactions
    if (!reactions) return undefined
    for (const scope of [signal.source, REACTION_ANY_DETECTOR]) {
      if (scope === undefined || !Object.hasOwn(reactions, scope)) continue
      const table = reactions[scope]
      if (table && Object.hasOwn(table, signal.kind)) return table[signal.kind]
    }
    return undefined
  }
}

/** Constructs {@link AnomalyFacet}, for a caller wiring one outside `createAuth`. */
export function anomalyFacet(events: Events.IBus, cfg: Partial<Anomaly.Cfg> = {}): AnomalyFacet {
  return new AnomalyFacet(events, cfg)
}
