import type { Events } from '~/core/events/events.types'
import { AuthError } from '../errors'
import type { Sessions } from '../sessions/sessions.types'
import { DEFAULT_HIJACK_POLICY } from './hijack.constants'
import type { Hijack } from './hijack.types'

/**
 * Hijack-detection facet. Stateless beyond the configured reactions; the
 * caller (server adapter) compares the inbound request's IP / UA with
 * the session's recorded values and applies the chosen reaction.
 *
 * Emits the canonical `suspicious` event regardless
 * of the reaction so audit pipelines see every drift.
 */
export class HijackFacet {
  private readonly _policy: Required<Hijack.Cfg>

  constructor(
    private readonly _events: Events.IBus,
    cfg: Hijack.Cfg = {},
  ) {
    this._policy = {
      onIpChange: cfg.onIpChange ?? DEFAULT_HIJACK_POLICY.onIpChange,
      onMissingSignal: cfg.onMissingSignal ?? DEFAULT_HIJACK_POLICY.onMissingSignal,
      onUserAgentChange: cfg.onUserAgentChange ?? DEFAULT_HIJACK_POLICY.onUserAgentChange,
    }
  }

  /**
   * Evaluate the request fingerprint against the session fingerprint.
   * Returns `{ ok: true }` when no drift detected, otherwise a reaction
   * the caller must act on (rotate / throw step-up / throw revoke).
   *
   * Always emits `suspicious` on drift, even when the configured reaction
   * is 'ignore', so the audit pipeline sees every change.
   */
  async evaluate(
    session: Sessions.Me,
    request: { ip?: string | null; userAgent?: string | null },
  ): Promise<Hijack.Evaluation> {
    // Evaluate IP + UA drift independently and return the strongest reaction. A missing baseline is
    // downgraded to `'rotate'` so audit fires without forcing step-up; a value the request dropped
    // follows `onMissingSignal`, because that side is the caller's to choose.
    type DriftSignal = 'ip-change' | 'user-agent-change'
    const drifts: Array<{
      signal: DriftSignal
      reaction: Hijack.Reaction
      from: string
      to: string
      score: number
    }> = []

    const ipDrift = isDrift(session.ip, request.ip)
    if (ipDrift) {
      const reaction = this._reactionFor(ipDrift, this._policy.onIpChange)
      drifts.push({
        signal: 'ip-change',
        reaction,
        from: session.ip ?? '',
        to: request.ip ?? '',
        score: 0.6,
      })
    }
    const uaDrift = isDrift(session.userAgent, request.userAgent)
    if (uaDrift) {
      const reaction = this._reactionFor(uaDrift, this._policy.onUserAgentChange)
      drifts.push({
        signal: 'user-agent-change',
        reaction,
        from: session.userAgent ?? '',
        to: request.userAgent ?? '',
        score: 0.8,
      })
    }

    if (drifts.length === 0) return { ok: true }

    // Cap diagnostic strings (UA / IP) at 256 chars before emit so
    // multi-KB headers cannot bloat OpenTelemetry / webhook payloads.
    for (const d of drifts) {
      await this._events.emit('suspicious', {
        ...(session.identityId && { identityId: session.identityId }),
        signal: d.signal,
        score: d.score,
        meta: { from: clipForDiagnostic(d.from), to: clipForDiagnostic(d.to) },
      })
    }

    // Pick the strongest reaction. Precedence: revoke > mfa > rotate > ignore.
    const severity: Record<Hijack.Reaction, number> = { ignore: 0, rotate: 1, mfa: 2, revoke: 3 }
    drifts.sort((a, b) => severity[b.reaction] - severity[a.reaction])
    const winner = drifts[0]
    // drifts.length === 0 already early-returned above; this narrows for TS.
    if (!winner || winner.reaction === 'ignore') return { ok: true }
    return {
      ok: false,
      reaction: winner.reaction,
      signal: winner.signal,
      from: clipForDiagnostic(winner.from),
      to: clipForDiagnostic(winner.to),
    }
  }

  private _reactionFor(drift: Exclude<Drift, null>, configured: Hijack.Reaction): Hijack.Reaction {
    if (drift === 'mismatch') return configured
    if (drift === 'no-baseline') return soften(configured)
    return this._policy.onMissingSignal === 'strict' ? configured : soften(configured)
  }

  /**
   * Translate a reaction into the throw the caller should bubble.
   * `'rotate'` is non-throwing; caller schedules a rotation via
   * SessionsFacet.rotateOrCreate({ purpose: 're-auth' }).
   */
  applyReaction(reaction: Hijack.Reaction): void {
    if (reaction === 'mfa') {
      throw new AuthError('AUTH_STEP_UP_REQUIRED', {
        challenge: { reason: 'hijack-policy' },
      })
    }
    if (reaction === 'revoke') {
      throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'hijack-policy' })
    }
  }
}

/** Compare a session baseline to a request value.
 *
 *   - `null`         - no drift (either both null/undefined or both equal)
 *   - `'mismatch'`   - both present, different values
 *   - `'no-baseline'`- the session recorded nothing to compare against
 *   - `'stripped'`   - the session recorded a value and the request omitted it
 *
 * The last two are kept apart because only one of them is the caller's choice. */
type Drift = null | 'mismatch' | 'no-baseline' | 'stripped'

function isDrift(baseline: string | null, current: string | null | undefined): Drift {
  // Treat null and undefined as equivalent absence.
  const b = baseline ?? undefined
  const c = current ?? undefined
  if (b === c) return null
  if (b === undefined) return 'no-baseline'
  if (c === undefined) return 'stripped'
  return 'mismatch'
}

/** One notch down, so a UA-less guest session does not force MFA on every request. A caller can
 * still configure `'ignore'` explicitly to suppress entirely. */
function soften(reaction: Hijack.Reaction): Hijack.Reaction {
  if (reaction === 'revoke' || reaction === 'mfa') return 'rotate'
  return reaction
}

/**
 * cap a caller-supplied diagnostic string
 * (IP or User-Agent) for safe inclusion in events + return value.
 * Long values appended with `...(truncated)` so operators see the
 * partial value but downstream sinks aren't asked to log/transmit a
 * 8 KiB UA per drift. The clip is content-preserving for typical
 * inputs (<=256 chars round-trip unchanged).
 */
const DIAGNOSTIC_MAX_LEN = 256
function clipForDiagnostic(s: string): string {
  if (s.length <= DIAGNOSTIC_MAX_LEN) return s
  return `${s.slice(0, DIAGNOSTIC_MAX_LEN)}...(truncated)`
}

/** Factory around {@link HijackFacet}, for callers who prefer functions to `new`. */
export function hijackFacet(events: Events.IBus, cfg: Partial<Hijack.Cfg> = {}): HijackFacet {
  return new HijackFacet(events, cfg)
}
