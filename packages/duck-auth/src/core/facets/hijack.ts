/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../errors'
import type { Events } from '../types/events'
import type { Session } from '../types/session'

/**
 * Reaction the hijack-detection policy applies when the request's
 * fingerprint diverges from the session's fingerprint.
 *
 *   ignore  - log the signal via `suspicious` event but allow the request
 *   rotate  - rotate the SID (force fresh transport issue) but allow
 *             the request after rotation
 *   mfa     - throw AUTH/STEP_UP_REQUIRED so the route surfaces a
 *             challenge; session continues at the current AAL until
 *             step-up satisfies
 *   revoke  - throw AUTH/SESSION_REVOKED + caller revokes the session
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export type HijackReaction = 'ignore' | 'rotate' | 'mfa' | 'revoke'

export interface HijackPolicyConfig {
  /** Reaction on IP change. Default 'rotate'. */
  onIpChange?: HijackReaction
  /** Reaction on User-Agent change. Default 'mfa'. */
  onUserAgentChange?: HijackReaction
}

const DEFAULT_HIJACK_POLICY: Required<HijackPolicyConfig> = {
  onIpChange: 'rotate',
  onUserAgentChange: 'mfa',
}

export type HijackEvaluation =
  | { ok: true }
  | { ok: false; reaction: HijackReaction; signal: 'ip-change' | 'user-agent-change'; from: string; to: string }

/**
 * Hijack-detection facet. Stateless beyond the configured reactions; the
 * caller (server adapter) compares the inbound request's IP / UA with
 * the session's recorded values and applies the chosen reaction.
 *
 * DESIGN section T1. Emits the canonical `suspicious` event regardless
 * of the reaction so audit pipelines see every drift.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class HijackFacet {
  private readonly _policy: Required<HijackPolicyConfig>

  constructor(
    private readonly _events: Events.IBus,
    cfg: HijackPolicyConfig = {},
  ) {
    this._policy = {
      onIpChange: cfg.onIpChange ?? DEFAULT_HIJACK_POLICY.onIpChange,
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
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async evaluate(session: Session.ISession, request: { ip?: string; userAgent?: string }): Promise<HijackEvaluation> {
    // IP change
    if (request.ip !== undefined && session.ip !== undefined && request.ip !== session.ip) {
      await this._events.emit('suspicious', {
        ...(session.identityId && { identityId: session.identityId }),
        signal: 'ip-change',
        score: 0.6,
        meta: { from: session.ip, to: request.ip },
      })
      if (this._policy.onIpChange !== 'ignore') {
        return {
          ok: false,
          reaction: this._policy.onIpChange,
          signal: 'ip-change',
          from: session.ip,
          to: request.ip,
        }
      }
    }
    // User-Agent change
    if (request.userAgent !== undefined && session.userAgent !== undefined && request.userAgent !== session.userAgent) {
      await this._events.emit('suspicious', {
        ...(session.identityId && { identityId: session.identityId }),
        signal: 'user-agent-change',
        score: 0.8,
        meta: { from: session.userAgent, to: request.userAgent },
      })
      if (this._policy.onUserAgentChange !== 'ignore') {
        return {
          ok: false,
          reaction: this._policy.onUserAgentChange,
          signal: 'user-agent-change',
          from: session.userAgent,
          to: request.userAgent,
        }
      }
    }
    return { ok: true }
  }

  /**
   * Translate a reaction into the throw the caller should bubble.
   * `'rotate'` is non-throwing; caller schedules a rotation via
   * SessionsFacet.rotateOrCreate({ purpose: 're-auth' }).
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  applyReaction(reaction: HijackReaction): void {
    if (reaction === 'mfa') {
      throw new AuthErrorObject('AUTH/STEP_UP_REQUIRED', {
        challenge: { reason: 'hijack-policy' },
      })
    }
    if (reaction === 'revoke') {
      throw new AuthErrorObject('AUTH/SESSION_REVOKED', { reason: 'hijack-policy' })
    }
  }
}

/**
 * Namespace merge for HijackFacet. Co-locates the config + input + output
 * shapes alongside the class via TS class+namespace merging. Consumers can
 * write either the flat name (e.g. HijackPolicyConfig) or the
 * namespaced form (HijackFacet.IPolicyConfig); both
 * resolve to the same type.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace HijackFacet {
  /** Alias for the flat `HijackPolicyConfig` type. */
  export type IPolicyConfig = HijackPolicyConfig
  /** Alias for the flat `HijackReaction` type. */
  export type IReaction = HijackReaction
  /** Alias for the flat `HijackEvaluation` type. */
  export type IEvaluation = HijackEvaluation
}
