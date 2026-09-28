import type { Events } from '~/core/events/events.types'
import { AuthError } from '../errors'
import type { SessionsImpl } from '../sessions'
import { SESSION_COLUMN_CAPS } from '../sessions/sessions.constants'
import type { Sessions } from '../sessions/sessions.types'
import { DEFAULT_HIJACK_POLICY, HIJACK_REACTION_SEVERITY } from './hijack.constants'
import type { Hijack } from './hijack.types'

/** Stateless beyond the configured reactions: the server adapter compares the request's IP and UA against
 *  the session's and applies the answer. Emits `suspicious` whatever the reaction, so audit sees every drift. */
export class HijackFacet {
  private readonly _policy: Required<Hijack.Cfg>

  constructor(
    private readonly _events: Events.IBus,
    private readonly _sessions: Pick<SessionsImpl, 'revokeByHash'>,
    cfg: Hijack.Cfg = {},
  ) {
    this._policy = {
      onIpChange: cfg.onIpChange ?? DEFAULT_HIJACK_POLICY.onIpChange,
      onMissingSignal: cfg.onMissingSignal ?? DEFAULT_HIJACK_POLICY.onMissingSignal,
      onUserAgentChange: cfg.onUserAgentChange ?? DEFAULT_HIJACK_POLICY.onUserAgentChange,
    }
    // A misspelled reaction ranks nowhere and `applyReaction` carries it out as nothing.
    for (const key of ['onIpChange', 'onUserAgentChange'] as const) {
      if (!Object.hasOwn(HIJACK_REACTION_SEVERITY, this._policy[key])) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: `hijackFacet: ${key} must be 'ignore', 'rotate', 'mfa' or 'revoke' (got ${String(this._policy[key])})`,
        })
      }
    }
    if (this._policy.onMissingSignal !== 'soften' && this._policy.onMissingSignal !== 'strict') {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `hijackFacet: onMissingSignal must be 'soften' or 'strict' (got ${String(this._policy.onMissingSignal)})`,
      })
    }
  }

  /** `{ ok: true }` when nothing drifted or every drift is ignored, otherwise the reaction the caller must
   *  act on. Emits `suspicious` on any drift, `'ignore'` included. */
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

    // Read as `SessionsImpl.create` stored the baseline - empty is absent, the rest cut to the column - or a
    // User-Agent longer than the column drifts on every request the browser sends.
    const ip = request.ip ? request.ip.slice(0, SESSION_COLUMN_CAPS.ip) : undefined
    const userAgent = request.userAgent ? request.userAgent.slice(0, SESSION_COLUMN_CAPS.userAgent) : undefined

    const ipDrift = isDrift(session.ip, ip)
    if (ipDrift) {
      const reaction = this._reactionFor(ipDrift, this._policy.onIpChange)
      drifts.push({
        signal: 'ip-change',
        reaction,
        from: session.ip ?? '',
        to: ip ?? '',
        score: 0.6,
      })
    }
    const uaDrift = isDrift(session.userAgent, userAgent)
    if (uaDrift) {
      const reaction = this._reactionFor(uaDrift, this._policy.onUserAgentChange)
      drifts.push({
        signal: 'user-agent-change',
        reaction,
        from: session.userAgent ?? '',
        to: userAgent ?? '',
        score: 0.8,
      })
    }

    if (drifts.length === 0) return { ok: true }

    for (const d of drifts) {
      // SECURITY: logged, not thrown - a sink that is down must not decide the reaction.
      try {
        // The session, not the addresses: `suspicious` is persisted wherever the bus is, and the raw values
        // stay in-process on the answer below.
        await this._events.emit('suspicious', {
          ...(session.identityId && { identityId: session.identityId }),
          signal: d.signal,
          score: d.score,
          meta: { sessionId: session.id },
        })
      } catch (err) {
        console.error('[@gentleduck/auth] hijack could not emit "suspicious":', err)
      }
    }

    drifts.sort((a, b) => HIJACK_REACTION_SEVERITY[b.reaction] - HIJACK_REACTION_SEVERITY[a.reaction])
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

  /** Carry a reaction out: `'revoke'` ends the session, then refuses; `'mfa'` refuses with a step-up.
   *  `'rotate'` does not throw: the caller re-issues the session with `SessionsImpl.rotateOrCreate({ purpose:
   *  'drift' })`. */
  async applyReaction(reaction: Hijack.Reaction, session: Pick<Sessions.Me, 'id'>): Promise<void> {
    if (reaction === 'mfa') {
      throw new AuthError('AUTH_STEP_UP_REQUIRED', {
        challenge: { reason: 'hijack-policy' },
      })
    }
    if (reaction === 'revoke') {
      // `orNull`: a session a concurrent request already ended is refused all the same.
      await this._sessions.revokeByHash(session.id).orNull()
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

/** A refusal drops to `'rotate'`, so a UA-less guest session does not force MFA on every request. `'ignore'`
 *  is still the way to suppress entirely. */
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

export function hijackFacet(
  events: Events.IBus,
  sessions: Pick<SessionsImpl, 'revokeByHash'>,
  cfg: Hijack.Cfg = {},
): HijackFacet {
  return new HijackFacet(events, sessions, cfg)
}
