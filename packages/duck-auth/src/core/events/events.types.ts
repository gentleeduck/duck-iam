import type { Identities } from '../identities'
import type { Sessions } from '../sessions'

/**
 * Typed event bus. Reference impl is in-memory; production swaps in Redis pub/sub
 * (`RedisEvents`) or Kafka (`KafkaEvents`) for multi-process / multi-region listeners.
 * Audit envelope (impersonation) flows on every event when present.
 */
export namespace Events {
  /**
   * Audit envelope stamped onto every event whose payload declares `audit`.
   *
   * Populated by `withAuditStamping()` (see `events.audit.ts`), which the engine wraps
   * its bus in, so emitters never build one. Two sources, in priority order: the ambient
   * envelope from `runWithAuditEnvelope()`, then the emitted session's own `actingAs`.
   * A payload that already carries `audit` is never overwritten.
   *
   * Absent means "no impersonation was in effect", **not** "unknown", but only for
   * events emitted inside a `runWithAuditEnvelope()` scope or carrying a session. See
   * that function's docs for the coverage boundary.
   */
  export interface Envelope {
    /** When the session is impersonating, real subject is recorded on every event. */
    actingAs?: Sessions.ActingAs
    /** Optional iam decision id when an action was authorized via iam-auth-bridge. */
    iamDecisionId?: string
  }

  export interface EventMap {
    'session.created': {
      session: Sessions.Me
      identity: Identities.Me | null
      audit?: Envelope
    }
    /**
     * Emitted after every rotation. `previousSessionId` is the **hashed** id of the
     * session that was rotated away from: present whenever the caller supplied a
     * `previousSid`, absent on a first-issue rotation. Audit consumers use it to chain
     * a session's lineage across rotations.
     */
    'session.rotated': { session: Sessions.Me; previousSessionId?: string; audit?: Envelope }
    'session.revoked': {
      sessionId: string
      identityId: string | null
      audit?: Envelope
    }
    'signin.success': {
      identity: Identities.Me
      factors: Sessions.Factor[]
      audit?: Envelope
    }
    'signin.failed': {
      providerId: string
      reason: string
      ip?: string
      audit?: Envelope
    }
    'signup.completed': { identity: Identities.Me; audit?: Envelope }
    lockout: { identityId: string; until: number; audit?: Envelope }
    'mfa.enrolled': {
      identityId: string
      method: Sessions.FactorMethod
      audit?: Envelope
    }
    'mfa.removed': {
      identityId: string
      method: Sessions.FactorMethod
      audit?: Envelope
    }
    'identity.linked': {
      identityId: string
      providerId: string
      audit?: Envelope
    }
    'identity.merged': {
      survivorId: string
      mergedFromId: string
      audit?: Envelope
    }
    'identity.impersonated': {
      realIdentityId: string
      targetIdentityId: string
      reason: string
      iamDecisionId?: string
    }
    'recovery.password.requested': { identityId: string; audit?: Envelope }
    'recovery.password.completed': { identityId: string; audit?: Envelope }
    'recovery.mfa.escalated': {
      identityId: string
      ticketId: string
      audit?: Envelope
    }
    suspicious: {
      identityId?: string
      signal: string
      score: number
      meta: Record<string, unknown>
      audit?: Envelope
    }
    /**
     * Published by the IAM side when an identity's authorization is revoked, so every
     * instance can drop cached decisions. duck-auth subscribes; it never emits this.
     * Carries no `audit` envelope precisely because it does not originate here.
     */
    'authz.revoked': { identityId: string; at: number }
    'maintenance.on': { message?: string; retryAfter?: number }
    'maintenance.off': Record<string, never>
  }

  export type EventName = keyof EventMap
  export type Handler<K extends EventName> = (payload: EventMap[K]) => void | Promise<void>
  export type Unsubscribe = () => void

  export interface IBus {
    on<K extends EventName>(event: K, handler: Handler<K>): Unsubscribe
    emit<K extends EventName>(event: K, payload: EventMap[K]): Promise<void>
  }

  /**
   * True when a payload declares `audit`. Both guards are load-bearing:
   * `T extends { audit?: Envelope }` matches everything (all-optional types are
   * assignable), and `keyof Record<string, never>` is `string`, which would drag in
   * `maintenance.off`.
   */
  export type DeclaresAudit<T> = string extends keyof T ? false : 'audit' extends keyof T ? true : false

  /** Events the stamper in `events.audit.ts` may write an {@link Envelope} onto. */
  export type AuditedEvent = {
    [K in EventName]: DeclaresAudit<EventMap[K]> extends true ? K : never
  }[EventName]

  /** The fields the stamper probes for on an outgoing payload. */
  export type Stampable = {
    audit?: Envelope
    session?: { actingAs?: Sessions.ActingAs | null }
  }
}
