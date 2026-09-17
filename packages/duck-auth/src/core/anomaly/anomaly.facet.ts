import { AuthError } from '~/core/errors'
import type { Events } from '~/core/events/events.types'
import type { Identities } from '../identities/identities.types'
import type { Sessions } from '../sessions/sessions.types'
import { clampScore, combineScores, DEFAULT_ANOMALY_CONFIG, REACTION_SCOPE } from './anomaly.constants'
import type { Anomaly } from './anomaly.types'

/**
 * A snapshot no detector can edit.
 *
 * The same object reached every detector, so the first one registered decided what the rest saw: a
 * plugin could blank the ip and silence the fingerprint detector that ran after it.
 */
function freezeSnapshot(req: Anomaly.RequestSnapshot): Readonly<Anomaly.RequestSnapshot> {
  return Object.freeze({ ...req, ...(req.geo && { geo: Object.freeze({ ...req.geo }) }) })
}

/**
 * structural type-guard for Anomaly.Signal. A signal from a
 * misbehaving detector that lacks the right shape (e.g. `null`,
 * `{}`, `{ kind: 42 }`) would otherwise reach `decide()` and crash
 * its `Number.isFinite(s.score)` access - see {@link Anomaly.evaluate}
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
  private readonly _cfg: Anomaly.Cfg

  constructor(
    private readonly _events: Events.IBus,
    cfg: Partial<Anomaly.Cfg> = {},
  ) {
    this._cfg = { ...DEFAULT_ANOMALY_CONFIG, ...cfg }
  }

  /**
   * Register a detector. Order does not affect the aggregate score.
   *
   * An id already registered is refused rather than appended: `register` appending blindly meant a
   * module loaded twice, or a plugin re-registering on reload, silently doubled that detector's
   * weight. A reload path calls `unregister` first.
   */
  register(detector: Anomaly.Detector): void {
    if (this._detectors.some((d) => d.id === detector.id)) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `anomaly detector "${detector.id}" is already registered; unregister it before registering again`,
      })
    }
    this._detectors.push(detector)
  }

  /**
   * Remove a previously-registered detector by id. No-op if not found, and
   * `false` says so - a typo in the id is otherwise indistinguishable from a
   * detector that really was removed.
   */
  unregister(id: string): boolean {
    const idx = this._detectors.findIndex((d) => d.id === id)
    if (idx < 0) return false
    this._detectors.splice(idx, 1)
    return true
  }

  /** Currently registered detector ids; UI / diagnostics. */
  list(): string[] {
    return this._detectors.map((d) => d.id)
  }

  /**
   * Run every detector + return the aggregate + recommended decision.
   *
   * Emits `suspicious` whenever the decision is anything but allow, and whenever the aggregate
   * crosses `threshold`. Gating the event on the score alone left the loudest outcomes unrecorded:
   * a non-finite score, a reaction override and a `threshold` raised above `stepUpAt` each produced
   * a deny or a step-up with nothing in the audit trail.
   *
   * Detectors run concurrently, each under its own timeout, so one slow plugin costs its own
   * latency rather than every later detector's as well. Exceptions are caught + logged so a
   * misbehaving plugin can never lock users out of authn.
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
      await this._events.emit('suspicious', {
        // Always present, empty string included: guarding the spread on truthiness produced a
        // suspicious record with no subject rather than one naming the id it actually saw.
        identityId: input.identity.id,
        meta: { decision, signals },
        score,
        signal: signals.map((s) => s.kind).join('+'),
      })
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
        accepted.push({ ...raw, score: Number.isFinite(raw.score) ? clampScore(raw.score) : raw.score, source: d.id })
      }
      return accepted
    } catch (err) {
      // Detector bug must not break authn flow; log + skip.
      console.error(`[@gentleduck/auth] anomaly detector "${d.id}" threw:`, err)
      return []
    } finally {
      clearTimeout(timer)
    }
  }

  /**
   * Map a signal set to a recommended decision. Standalone so callers
   * can re-decide on cached signals or test the ladder without invoking
   * detectors.
   *
   * Decision order (any match short-circuits):
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
    const score = combineScores(finite.map((s) => s.score))
    // Non-finite score collapses every comparison and falls through to allow. The score still
    // reports what the other detectors found, so the audit record is not blank.
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

  /** The scoped key wins, so a plugin cannot claim an override written for another detector. */
  private _reactionFor(signal: Anomaly.Signal): Anomaly.Decision | undefined {
    const reactions = this._cfg.reactions
    if (!reactions) return undefined
    return reactions[`${signal.source}${REACTION_SCOPE}${signal.kind}`] ?? reactions[signal.kind]
  }
}

/** Factory around {@link AnomalyFacet}, for callers who prefer functions to `new`. */
export function anomalyFacet(events: Events.IBus, cfg: Partial<Anomaly.Cfg> = {}): AnomalyFacet {
  return new AnomalyFacet(events, cfg)
}
