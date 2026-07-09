/** Provider domain — auth providers/intents, events, anomaly detection. */

import type { Identity } from '~/core/identities/identities.types'
import type { Session } from '~/core/sessions/sessions.types'

/**
 * A sign-in method. Providers are pure logic: they read stores, validate input,
 * and return Intents; the framework adapter executes the Intents against the
 * actual HTTP Request/Response. This keeps providers HTTP-free and unit-testable.
 */

/**
 * Typed event bus. Reference impl is in-memory; production swaps in Redis pub/sub
 * (`RedisEvents`) or Kafka (`KafkaEvents`) for multi-process / multi-region listeners.
 * Audit envelope (impersonation) flows on every event when present.
 */
export namespace Events {
  export interface Envelope {
    /** When the session is impersonating, real subject is recorded on every event. */
    actingAs?: Session.ActingAs
    /** Optional iam decision id when an action was authorized via iam-auth-bridge. */
    iamDecisionId?: string
  }

  export interface EventMap {
    'session.created': {
      session: Session.Me
      identity: Identity.Me | null
      audit?: Envelope
    }
    'session.rotated': { session: Session.Me; audit?: Envelope }
    'session.revoked': {
      sessionId: string
      identityId: string | null
      audit?: Envelope
    }
    'signin.success': {
      identity: Identity.Me
      factors: Session.Factor[]
      audit?: Envelope
    }
    'signin.failed': {
      providerId: string
      reason: string
      ip?: string
      audit?: Envelope
    }
    'signup.completed': { identity: Identity.Me; audit?: Envelope }
    lockout: { identityId: string; until: number; audit?: Envelope }
    'mfa.enrolled': {
      identityId: string
      method: Session.FactorMethod
      audit?: Envelope
    }
    'mfa.removed': {
      identityId: string
      method: Session.FactorMethod
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
