import { AuthError } from '~/core/errors'
import type { Events } from '~/core/events/events.types'
import type { Identities } from '../identities/identities.types'
import type { Sessions } from '../sessions/sessions.types'
import {
  clampScore,
  combineScores,
  DEFAULT_ANOMALY_CONFIG,
  DETECTOR_TIMEOUT_MAX_MS,
  REACTION_ANY_DETECTOR,
} from './anomaly.constants'
import type { Anomaly } from './anomaly.types'

/** A snapshot no detector can edit, so the first one registered cannot decide what the rest see. */
function freezeSnapshot(req: Anomaly.RequestSnapshot): Readonly<Anomaly.RequestSnapshot> {
  return Object.freeze({ ...req, ...(req.geo && { geo: Object.freeze({ ...req.geo }) }) })
}

/** What a detector is allowed to hand back: a `Signal` whose `evidence` may be absent, which
 *  {@link AnomalyFacet.evaluate} fills in. */
type RawSignal = Omit<Anomaly.Signal, 'evidence'> & { evidence?: Record<string, unknown> }

/** Structural guard, so a misbehaving detector's malformed signal is skipped before `decide()` reads
 *  `.score` off it. */
function isValidSignal(raw: unknown): raw is RawSignal {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return false
  // `kind` is checked as a string, never against the union: a plugin may define new kinds.
  if (!('kind' in raw) || typeof raw.kind !== 'string' || raw.kind.length === 0) return false
  if (!('score' in raw) || typeof raw.score !== 'number') return false
  // Absent is fine and reads as `{}`. Anything that is not a record is not: the type promises one, and
  // every sink of `suspicious` - and every `Object.keys` in an audit view - believes it.
  if ('evidence' in raw && (typeof raw.evidence !== 'object' || raw.evidence === null || Array.isArray(raw.evidence)))
    return false
  return true
}

/** Runs the registered detectors per request, typically after `resolveSession`, sums their scores and
 *  answers with a recommended decision so callers branch on one field rather than re-implementing the
 *  threshold ladder. {@link AnomalyFacet.decide} exposes the same ladder standalone. */
export class AnomalyFacet {
  private readonly _detectors: Anomaly.Detector[] = []
  private readonly _cfg: Anomaly.Cfg

  constructor(
    private readonly _events: Events.IBus,
    cfg: Partial<Anomaly.Cfg> = {},
  ) {
    this._cfg = { ...DEFAULT_ANOMALY_CONFIG, ...cfg }
    // SECURITY: every way these four can be wrong fails open. `score >= NaN` is false, so a threshold
    // that is not a number never denies and never steps up, and `setTimeout` floors a non-finite or
    // oversized delay, abandoning every detector before it answers - detection off, and nothing said.
    for (const key of ['threshold', 'stepUpAt', 'denyAt'] as const) {
      if (!Number.isFinite(this._cfg[key]) || this._cfg[key] < 0 || this._cfg[key] > 1) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: `anomalyFacet: ${key} must be a number between 0 and 1 (got ${this._cfg[key]})`,
        })
      }
    }
    // A misspelled decision used to do nothing at all: `severity['denied']` is undefined and every
    // comparison against it is false, so the override the operator wrote never applied and never said so.
    for (const [detectorId, table] of Object.entries(this._cfg.reactions ?? {})) {
      if (typeof table !== 'object' || table === null || Array.isArray(table)) {
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
    const timeout = this._cfg.detectorTimeoutMs
    if (!Number.isFinite(timeout) || timeout < 1 || timeout > DETECTOR_TIMEOUT_MAX_MS) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `anomalyFacet: detectorTimeoutMs must be a number between 1 and ${DETECTOR_TIMEOUT_MAX_MS} (got ${timeout})`,
      })
    }
  }

  /** Register a detector; order does not affect the aggregate. An id already registered is refused
   *  rather than appended, or a module loaded twice would double that detector's weight. */
  register(detector: Anomaly.Detector): void {
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

  /** Remove a detector by id. `false` when nothing matched, so a typo is distinguishable from a
   *  detector that really was removed. */
  unregister(id: string): boolean {
    const idx = this._detectors.findIndex((d) => d.id === id)
    if (idx < 0) return false
    this._detectors.splice(idx, 1)
    return true
  }

  /** The ids of the registered detectors, in registration order; `evaluate` runs them concurrently. */
  list(): string[] {
    return this._detectors.map((d) => d.id)
  }

  /**
   * Detectors run concurrently under their own timeouts, and an exception is caught and logged, so no
   * plugin can lock users out of authn.
   */
  async evaluate(input: {
    session: Sessions.Me
    identity: Identities.Me
    req: Anomaly.RequestSnapshot
  }): Promise<Anomaly.Result> {
    const ctx = { identity: input.identity, req: freezeSnapshot(input.req), session: input.session }
    const collected = await Promise.all(this._detectors.map((d) => this._runDetector(d, ctx)))
    const signals = collected.flat()

    const { decision, score } = this._aggregate(signals)
    if (decision !== 'allow' || (score >= this._cfg.threshold && signals.length > 0)) {
      // SECURITY: the verdict is already decided and the emit cannot improve it, so a bus that rejects
      // is logged rather than thrown. `resolveSession` answers a throw from here by dropping the result,
      // and the emit only runs on the requests that scored - the ones the verdict is for.
      try {
        await this._events.emit('suspicious', {
          // Always present, empty string included: guarding the spread on truthiness produced a
          // suspicious record with no subject rather than one naming the id it actually saw.
          identityId: input.identity.id,
          meta: { decision, signals },
          score,
          signal: signals.map((s) => s.kind).join('+'),
        })
      } catch (err) {
        console.error('[@gentleduck/auth] anomaly could not emit "suspicious":', err)
      }
    }
    return { decision, score, signals }
  }

  private async _runDetector(
    d: Anomaly.Detector,
    ctx: { session: Sessions.Me; identity: Identities.Me; req: Readonly<Anomaly.RequestSnapshot> },
  ): Promise<Anomaly.Signal[]> {
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      const out = await Promise.race([
        d.evaluate(ctx),
        new Promise<never>((_, reject) => {
          timer = setTimeout(
            () => reject(new Error(`detector "${d.id}" exceeded ${this._cfg.detectorTimeoutMs}ms`)),
            this._cfg.detectorTimeoutMs,
          )
        }),
      ])
      if (!Array.isArray(out)) {
        console.error(`[@gentleduck/auth] anomaly detector "${d.id}" returned non-array; skipping`)
        return []
      }
      const accepted: Anomaly.Signal[] = []
      for (const raw of out) {
        if (!isValidSignal(raw)) {
          console.error(`[@gentleduck/auth] anomaly detector "${d.id}" returned invalid signal; skipping`)
          continue
        }
        // `source` is stamped here, never read from the detector: it is what lets an operator scope
        // a reaction to the detector that earned it.
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
      return []
    } finally {
      clearTimeout(timer)
    }
  }

  /**
   * Standalone, so callers can re-decide on cached signals. Order, any match short-circuiting:
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

  private _aggregate(signals: Anomaly.Signal[]): { score: number; decision: Anomaly.Decision } {
    const reactions = this._cfg.reactions
    const scored = signals.filter((s) => this._reactionFor(s) !== 'allow')
    const finite = scored.filter((s) => Number.isFinite(s.score))
    // SECURITY: clamped here too, because `decide` is the other intake and takes its signals from the
    // caller. Noisy-or is defined over 0..1: above 1 two scores multiply back to a positive, so the
    // aggregate *fell* as evidence was added.
    const score = combineScores(finite.map((s) => clampScore(s.score)))
    // Checked explicitly, because a NaN or an Infinity collapses every comparison below and would
    // otherwise reach the final `allow`. The score still reports what the other detectors found, so
    // the audit record is not blank.
    if (finite.length !== scored.length) return { decision: 'deny', score }
    if (score >= this._cfg.denyAt) return { decision: 'deny', score }
    if (reactions) {
      let kindDecision: Anomaly.Decision = 'allow'
      const severity: Record<Anomaly.Decision, number> = { allow: 0, deny: 2, 'step-up': 1 }
      for (const s of scored) {
        const r = this._reactionFor(s)
        if (!r) continue
        if (severity[r] > severity[kindDecision]) kindDecision = r
      }
      if (severity[kindDecision] > 0) return { decision: kindDecision, score }
    }
    if (score >= this._cfg.stepUpAt) return { decision: 'step-up', score }
    return { decision: 'allow', score }
  }

  /** The detector's own table wins over the `'*'` one, so a plugin cannot claim an override written for
   *  another detector. `Object.hasOwn` at both levels: a detector id or kind spelling a prototype member
   *  is answered no rather than handed `Object.prototype`'s. */
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
