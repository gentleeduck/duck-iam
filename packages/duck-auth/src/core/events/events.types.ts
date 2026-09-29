import type { Identities } from '../identities'
import type { Sessions } from '../sessions'

/** The typed event bus. In-memory by default; `RedisEvents` takes over for listeners spread
 *  across processes or regions. The audit envelope rides along on every event that declares one. */
export namespace Events {
  /**
   * Stamped onto every event whose payload declares `audit`. `withAuditStamping()`, which the engine wraps its
   * bus in, fills it, so emitters never build one. It reads the ambient envelope from `runWithAuditEnvelope()`
   * first, then the emitted session's own `actingAs`, and never overwrites a payload that already carries one.
   * Absent means no impersonation was in effect rather than unknown, but only inside a `runWithAuditEnvelope()`
   * scope or on an event carrying a session.
   */
  export interface Envelope {
    /** When the session is impersonating, real subject is recorded on every event. */
    actingAs?: Sessions.ActingAs
    /** Who performed the action, from the ambient actor context. The payload's `identityId` is the subject and
     *  this is the operator; they differ when someone acts on another account. Absent when no actor was bound. */
    actorId?: string
  }

  /** Every event the engine emits, keyed by name, to its payload. */
  export interface EventMap {
    /** A session was created. */
    'session.created': {
      session: Sessions.Me
      identity: Identities.Me | null
      audit?: Envelope
    }
    /**
     * A session died of age rather than by request - the sliding TTL, the hard absolute cap, an elapsed
     * impersonation window, or a `gc()` sweep.
     *
     * Deliberately not `session.revoked`: a consumer has to be able to tell "the system aged this out"
     * from "someone revoked this", and folding them together makes the revocation audit trail lie and
     * hides organic churn inside deliberate action.
     *
     * `sessionId` and `identityId` are absent for a `gc()` sweep, which knows only how many rows it took;
     * `count` is set only there, and is 1 everywhere else.
     *
     * No `audit` envelope, which is what keeps it out of `AUDITED_EVENTS`: that envelope names who did a
     * thing, and nobody did this one. Stamping the holder of a dead token onto it would invite reading
     * "who expired this session" out of a field that answers a different question.
     */
    'session.expired': {
      sessionId?: string
      identityId?: string | null
      reason: 'sliding' | 'absolute' | 'impersonation' | 'gc'
      count?: number
    }
    /** Emitted after every rotation. `previousSessionId` is the hashed id rotated away from, present whenever
     *  the caller supplied a `previousSid`, and it is what chains a session's lineage for audit. */
    'session.rotated': { session: Sessions.Me; previousSessionId?: string; audit?: Envelope }
    /** A session was deleted by a revoke, a cascade, or a rotation that replaced it. */
    'session.revoked': {
      sessionId: string
      identityId: string | null
      audit?: Envelope
    }
    /** A sign-in finished and its session was issued. */
    'signin.success': {
      identity: Identities.Me
      factors: Sessions.Factor[]
      audit?: Envelope
    }
    /** A sign-in or link attempt was refused; `reason` is for logs, never for the caller. */
    'signin.failed': {
      providerId: string
      reason: string
      ip?: string
      audit?: Envelope
    }
    /** A sign-up finished and its identity exists. */
    'signup.completed': { identity: Identities.Me; audit?: Envelope }
    /** An identity is locked out until `until` (epoch ms). */
    lockout: { identityId: string; until: number; audit?: Envelope }
    /** A second factor was added. */
    'mfa.enrolled': {
      identityId: string
      method: Sessions.FactorMethod
      audit?: Envelope
    }
    /** A second factor was removed. */
    'mfa.removed': {
      identityId: string
      method: Sessions.FactorMethod
      audit?: Envelope
    }
    /** A provider login was attached to an identity. */
    'identity.linked': {
      identityId: string
      providerId: string
      audit?: Envelope
    }
    /** The mirror of `identity.linked`.
     *  SECURITY: this is the half an account takeover performs, dropping the real owner's login so only the
     *  attacker's route is left. */
    'identity.unlinked': {
      identityId: string
      providerId: string
      /** Whether the caller passed `allowLockout` to override the last-factor guard. */
      allowedLockout: boolean
      audit?: Envelope
    }
    /** An identity erased for good. The `operatorId` given to `erase` arrives as `audit.actorId`. */
    'identity.erased': {
      identityId: string
      reason: string
      audit?: Envelope
    }
    /** An operator opened an impersonation window. */
    'identity.impersonated': {
      realIdentityId: string
      targetIdentityId: string
      reason: string
      /** Which IAM decision let this through. An impersonation nobody can trace to an authorization
       *  is the one entry an audit log cannot afford to be missing. */
      iamDecisionId?: string
      /** WARN: the flow sets this itself; it emits outside any request scope, so the stamper finds nothing. */
      audit?: Envelope
    }
    /** The close of a window, however it closed. */
    'identity.impersonation.ended': {
      sessionId: string
      realIdentityId: string
      /** The impersonated subject: the session's own `identityId`, which a guest row leaves null. */
      targetIdentityId: string | null
      endedBy: 'release' | 'revoke' | 'expiry'
      audit?: Envelope
    }
    /** A password-reset mail was sent. */
    'recovery.password.requested': { identityId: string; audit?: Envelope }
    /** A password was reset through its mailed link. */
    'recovery.password.completed': { identityId: string; audit?: Envelope }
    /** A second factor satisfied by a recovery credential instead of the factor itself. `credentialId`
     *  is the backup code that was spent, already burnt and revoked by the time this is emitted. */
    'recovery.mfa.escalated': {
      identityId: string
      credentialId: string
      audit?: Envelope
    }
    /** A detector flagged this request: anomaly, hijack, or a replayed factor. */
    suspicious: {
      identityId?: string
      signal: string
      score: number
      meta: Record<string, unknown>
      audit?: Envelope
    }
    /** An identity joined an org with `roles`. */
    'org.member.added': { orgId: string; identityId: string; roles: string[]; audit?: Envelope }
    /** An identity left an org. */
    'org.member.removed': { orgId: string; identityId: string; audit?: Envelope }
    /** `roles` is the whole set the member now holds, as stored. */
    'org.roles.set': { orgId: string; identityId: string; roles: string[]; audit?: Envelope }
    /** Published by the IAM side when an identity's authorization is revoked, so every instance drops its cached
     *  decisions. duck-auth only subscribes, which is why this carries no `audit` envelope. */
    'authz.revoked': { identityId: string; at: number }
  }

  /** The name of any event on the bus. */
  export type EventName = keyof EventMap
  /** A listener for event `K`. */
  export type Handler<K extends EventName> = (payload: EventMap[K]) => void | Promise<void>
  /** Removes the listener it was returned for. */
  export type Unsubscribe = () => void
  /** Where a handler runs: `origin` on the server that emitted, inside its async context; `fleet` on every server. */
  export type Delivery = 'origin' | 'fleet'
  /** How `on()` registers a handler. */
  export interface OnOptions {
    /** Default `fleet`. */
    delivery?: Delivery
  }

  /** What the engine needs from a bus: subscribe and publish. */
  export interface IBus {
    /** Subscribes `handler` to `event`. A `fleet` handler on another server gets a copy of the payload,
     *  outside the emitter's request context; an `origin` one gets the emitter's payload and context. */
    on<K extends EventName>(event: K, handler: Handler<K>, opts?: OnOptions): Unsubscribe
    /** Publishes `payload` to every listener of `event`. */
    emit<K extends EventName>(event: K, payload: EventMap[K]): Promise<void>
    /** The handlers `event` has in this process, of both kinds. `strict()` skips its `lockout` check without it. */
    listenerCount?<K extends EventName>(event: K): number
    /** The events with a `fleet` handler in this process. `strict()` reads it off an in-process bus. */
    fleetEvents?(): EventName[]
  }

  /** True when a payload declares `audit`.
   *  WARN: `T extends { audit?: Envelope }` matches everything, since all-optional types are assignable,
   *  and the `string extends keyof T` guard holds the line for an empty payload, whose `keyof` is `string`. */
  export type DeclaresAudit<T> = string extends keyof T ? false : 'audit' extends keyof T ? true : false

  /** Events the stamper in `events.audit.ts` may write an {@link Envelope} onto. */
  export type AuditedEvent = {
    [K in EventName]: DeclaresAudit<EventMap[K]> extends true ? K : never
  }[EventName]
}
