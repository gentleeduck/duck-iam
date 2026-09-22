import type { Events } from '~/core/events/events.types'
import { AuthError } from '../errors'
import type { Sessions } from '../sessions/sessions.types'
import { DEFAULT_HIJACK_POLICY } from './hijack.constants'
import type { Hijack } from './hijack.types'

/** Stateless beyond the configured reactions: the server adapter compares the request's IP and UA against
 *  the session's and applies the answer. Emits `suspicious` whatever the reaction, so audit sees every drift. */
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

  /** `{ ok: true }` when nothing drifted, otherwise the reaction the caller must act on. Emits
   *  `suspicious` on any drift, `'ignore'` included. */
  async evaluate(
    session: Sessions.Me,
    request: { ip?: string | null; userAgent?: string | null },
  ): Promise<Hijack.Evaluation> {
    // IP and UA drift independently, and the strongest reaction wins. A missing baseline softens to
    // `'rotate'` so audit fires without forcing step-up; a value the request dropped follows
    // `onMissingSignal`, because that side is the caller's to choose.
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

    // Capped before emit, so a multi-KB header cannot bloat an OpenTelemetry or webhook payload.
    for (const d of drifts) {
      await this._events.emit('suspicious', {
        ...(session.identityId && { identityId: session.identityId }),
        signal: d.signal,
        score: d.score,
        meta: { from: clipForDiagnostic(d.from), to: clipForDiagnostic(d.to) },
      })
    }

    // Precedence: revoke > mfa > rotate > ignore.
    const severity: Record<Hijack.Reaction, number> = { ignore: 0, rotate: 1, mfa: 2, revoke: 3 }
    drifts.sort((a, b) => severity[b.reaction] - severity[a.reaction])
    const winner = drifts[0]
    // The empty case already returned above; this only narrows for TS.
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

  /** The throw a reaction becomes. `'rotate'` does not throw: the caller schedules one with
   *  `SessionsImpl.rotateOrCreate({ purpose: 're-auth' })`. */
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

/** A session baseline against a request value. */
type Drift = null | 'mismatch' | 'no-baseline' | 'stripped'

function isDrift(baseline: string | null, current: string | null | undefined): Drift {
  // null and undefined are the same absence here.
  const b = baseline ?? undefined
  const c = current ?? undefined
  if (b === c) return null
  if (b === undefined) return 'no-baseline'
  if (c === undefined) return 'stripped'
  return 'mismatch'
}

/** One notch down, so a UA-less guest session does not force MFA on every request. `'ignore'` is still
 *  the way to suppress entirely. */
function soften(reaction: Hijack.Reaction): Hijack.Reaction {
  if (reaction === 'revoke' || reaction === 'mfa') return 'rotate'
  return reaction
}

/** Marks a clipped value `...(truncated)`, so operators still see the partial one without a sink being
 *  handed an 8 KiB UA per drift. */
const DIAGNOSTIC_MAX_LEN = 256
function clipForDiagnostic(s: string): string {
  if (s.length <= DIAGNOSTIC_MAX_LEN) return s
  return `${s.slice(0, DIAGNOSTIC_MAX_LEN)}...(truncated)`
}

export function hijackFacet(events: Events.IBus, cfg: Partial<Hijack.Cfg> = {}): HijackFacet {
  return new HijackFacet(events, cfg)
}
