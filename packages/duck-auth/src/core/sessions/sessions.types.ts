import type { Identities } from '../identities'
import type { TenantContext } from '../tenant/tenant.types'

export const AUTH_SESSION_KINDS = ['guest', 'user', 'apikey'] as const

export const AUTH_SESSION_FACTOR_METHODS = [
  'password',
  'passkey',
  'totp',
  'oauth',
  'saml',
  'magic-link',
  'webauthn',
  'sms',
  'api-key',
  'backup-code',
] as const

const KIND_VALUES: ReadonlySet<string> = new Set<string>(AUTH_SESSION_KINDS)
const FACTOR_METHOD_VALUES: ReadonlySet<string> = new Set<string>(AUTH_SESSION_FACTOR_METHODS)

/** Derived from the constant, not restated: a kind added to one and not the other would be refused by
 *  every reader while the source of truth still called it valid. */
export function isSessionKind(v: unknown): v is Sessions.Kind {
  return typeof v === 'string' && KIND_VALUES.has(v)
}

/** {@link isSessionKind} for factor methods, and derived for the same reason. */
export function isFactorMethod(v: unknown): v is Sessions.FactorMethod {
  return typeof v === 'string' && FACTOR_METHOD_VALUES.has(v)
}

/** The session row, its assurance levels, and the store contract over it. */
export namespace Sessions {
  /** NIST 800-63B Authentication Assurance Levels. */
  export type AAL = 1 | 2 | 3

  export type FactorMethod = (typeof AUTH_SESSION_FACTOR_METHODS)[number]

  export interface Factor {
    method: FactorMethod
    completedAt: Date
  }

  export type Kind = (typeof AUTH_SESSION_KINDS)[number]

  export type ActingAs = {
    realIdentityId: string
    startedAt: Date
    reason: string
    expiresAt: Date
  }

  /** Enough to name the session in a `session.revoked` event. */
  export type Revoked = Pick<Me, 'id' | 'identityId'>

  export type Me = {
    /** The sha-256 of the sid; the sid itself never reaches the store. */
    id: string
    /** `null` on a guest session, the one kind that names nobody. */
    identityId: string | null
    /** `null` is a global session, which a tenant-scoped read does not see. */
    tenantId: string | null
    /** Which credential opened it; an `apikey` session is a machine caller, not a person. */
    kind: Kind
    /** The assurance level reached: 2 once a second factor was presented. */
    aal: AAL
    /** Every factor presented, with when; `aal` is what they add up to. */
    factors: Factor[]
    /** Per-session CSRF token hash (sha-256). Cookie carries the plaintext under __Host-. */
    csrfHash: string | null
    /** Captured at create, never refreshed; hijack detection reads the drift. */
    ip: string | null
    /** Captured at create like `ip`, and compared for the same drift. */
    userAgent: string | null
    /** The device fingerprint at create, where a detector composed one. */
    fingerprint: string | null
    createdAt: Date
    /** Moves on every write to the row, a rotation or not. SQL maintains it through `$onUpdate`; the
     *  memory and redis stores stamp it themselves. */
    updatedAt: Date
    /** Moves on every rotation; `createdAt` stays at the original sign-in. */
    rotatedAt: Date
    /** The sliding deadline, pushed out as the session is used and never past `absoluteExpiresAt`. */
    expiresAt: Date
    /** The hard cap, fixed at create; no rotation or touch moves it. */
    absoluteExpiresAt: Date
    /** Whether a factor was presented recently enough for a privileged operation. */
    fresh: boolean
    /** The impersonation window, when one is open. The only case where a session's author differs from its
     *  subject, which is why the row carries no `createdBy`. */
    actingAs: ActingAs | null
  }

  /** A row minus the one field a caller outside the server must never hold. */
  export type Public = Omit<Me, 'csrfHash'>

  /** Every nullable column explicit; `SessionsImpl.create` coalesces {@link MintInput} into it. */
  export type CreateInput = Omit<Me, 'tenantId' | 'csrfHash' | 'ip' | 'userAgent' | 'fingerprint' | 'actingAs'> & {
    tenantId: string | null
    csrfHash: string | null
    ip: string | null
    userAgent: string | null
    fingerprint: string | null
    actingAs: ActingAs | null
  }

  export type Store = {
    create(s: CreateInput): Promise<void>
    /** The session behind a cookie's hash. A hash matching nothing is `AUTH_SESSION_REVOKED`: one that never
     *  existed and one that was ended must read the same. */
    getByHash(sidHash: string): Promise<Me>
    /**
     * Patch a session. `expectedUpdatedAt` is an optional optimistic guard: supplied, the write lands only
     * if the stored `updatedAt` still matches, and a mismatch is `AUTH_STALE_WRITE` rather than a silent
     * overwrite. Omitted, the write is unconditional, as it always was.
     *
     * `updatedAt` is the token rather than a `version` column, which `Me` does not have and which would be
     * a migration in four dialects, and rather than `rotatedAt`, which only a rotation moves - a `touch()`
     * landing on a step-up would compare equal and discard the AAL upgrade, which is the race this guards.
     * Every store stamps `updatedAt` on every write, which is what makes it usable and what
     * `store-compliance` already pins.
     *
     * WARN: `Date` is millisecond-resolution, so two writes inside one millisecond still compare equal.
     */
    update(id: string, patch: Partial<Me>, expectedUpdatedAt?: Date): Promise<Me>
    delete(id: string): Promise<void>
    /** Every session of an identity, narrowed to one tenant by `ctx`. Identities are global, so an unfiltered
     *  read hands one tenant the IP, user-agent and existence of every session another issued. A named
     *  `tenantId` matches exactly, so a global (`null`) session is not visible to it. */
    listByIdentity(identityId: string, ctx?: TenantContext): Promise<Me[]>
    /** Sign an identity out, scoped as {@link Sessions.Store.listByIdentity} is.
     *  WARN: unscoped it ends every session the identity has anywhere, other tenants' included. */
    deleteAllForIdentity(identityId: string, ctx?: TenantContext): Promise<void>
    /** Periodic GC, scheduled by the caller, counting each row it reconciled once. An implementation that can
     *  run on several instances at once MUST serialise itself, as `RedisSessionImpl` does with a `gc:lease`. */
    gc(now: number): Promise<{ deleted: number }>

    /** The deletes above over a set, each answering the sessions it removed. */
    deleteAllForIdentities(identityIds: string[]): Promise<Revoked[]>
    deleteMany(ids: string[]): Promise<Revoked[]>
  }

  export type Cfg = {
    /** Sliding TTL in ms. Default 7 days. */
    ttlMs: number
    /** Hard absolute cap in ms. Default 30 days. */
    absoluteTtlMs: number
    /** Window in ms where a session counts as "fresh" since the last factor. Default 5 min. */
    freshnessMs: number
    /**
     * Most concurrent sessions one identity may hold. Over the cap, the oldest by `createdAt` is revoked
     * to make room. Unset means unlimited, which is the historical behaviour and the default.
     *
     * Guests are not counted: `identityId === null` is not an identity to scope a limit to.
     *
     * WARN: setting it puts a `listByIdentity` on every sign-in. An operator turning it on is choosing
     * that read.
     */
    maxSessionsPerIdentity?: number
  }

  export type MintInput = {
    identityId: string | null
    kind: Kind
    aal: AAL
    factors: Factor[]
    tenantId?: string | null
    ip?: string | null
    userAgent?: string | null
    fingerprint?: string | null
    actingAs?: ActingAs | null
    identity?: Identities.Me | null
    /** An upper bound on `expiresAt`, never an extension: the facet's own ttl still wins when it is sooner.
     *  The m2m grant sets it so a session expires with the token it was minted for. */
    maxExpiresAt?: Date
    /** Shortens this row's whole life, `absoluteExpiresAt` included. Only ever shortens. */
    ttlMs?: number
  }

  export interface RotateInput extends MintInput {
    /** Whether the previous SID is revoked outright, downgraded (step-up keeps it alive at a lower AAL), or
     *  left alone (impersonation runs alongside the original). */
    purpose:
      | 'signin'
      | 're-auth'
      | 'step-up'
      | 'step-down'
      | 'credential-change'
      | 'impersonate-start'
      | 'impersonate-release'
      /** A guest session becoming a named one; the guest row is revoked. */
      | 'guest-promotion'
      /** The first session of a new account. Not `guest-promotion`, since most signups have no prior session
       *  to promote, but revoked alike: whatever the caller came in on does not survive. */
      | 'sign-up'
    previousSid?: string
  }
}
