import type { Identity } from './identity'
import type { Session } from './session'

/**
 * Typed event bus. Reference impl is in-memory; production swaps in Redis pub/sub
 * (`RedisEvents`) or Kafka (`KafkaEvents`) for multi-process / multi-region listeners.
 * Audit envelope (impersonation) flows on every event when present.
 */
export namespace Events {
  export interface AuditEnvelope {
    /** When the session is impersonating, real subject is recorded on every event. */
    actingAs?: Session.ActingAs
    /** Optional iam decision id when an action was authorized via iam-auth-bridge. */
    iamDecisionId?: string
  }

  export interface EventMap {
    'session.created': {
      session: Session.ISession
      identity: Identity.IIdentity | null
      audit?: AuditEnvelope
    }
    'session.rotated': { session: Session.ISession; audit?: AuditEnvelope }
    'session.revoked': {
      sessionId: string
      identityId: string | null
      audit?: AuditEnvelope
    }
    'signin.success': {
      identity: Identity.IIdentity
      factors: Session.Factor[]
      audit?: AuditEnvelope
    }
    'signin.failed': {
      providerId: string
      reason: string
      ip?: string
      audit?: AuditEnvelope
    }
    'signup.completed': { identity: Identity.IIdentity; audit?: AuditEnvelope }
    lockout: { identityId: string; until: number; audit?: AuditEnvelope }
    'mfa.enrolled': {
      identityId: string
      method: Session.FactorMethod
      audit?: AuditEnvelope
    }
    'mfa.removed': {
      identityId: string
      method: Session.FactorMethod
      audit?: AuditEnvelope
    }
    'identity.linked': {
      identityId: string
      providerId: string
      audit?: AuditEnvelope
    }
    'identity.merged': {
      survivorId: string
      mergedFromId: string
      audit?: AuditEnvelope
    }
    'identity.impersonated': {
      realIdentityId: string
      targetIdentityId: string
      reason: string
      iamDecisionId?: string
    }
    'recovery.password.requested': { identityId: string; audit?: AuditEnvelope }
    'recovery.password.completed': { identityId: string; audit?: AuditEnvelope }
    'recovery.mfa.escalated': {
      identityId: string
      ticketId: string
      audit?: AuditEnvelope
    }
    suspicious: {
      identityId?: string
      signal: string
      score: number
      meta: Record<string, unknown>
      audit?: AuditEnvelope
    }
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
}
