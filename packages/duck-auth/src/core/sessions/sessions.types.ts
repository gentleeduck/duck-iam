/** Session domain + lifecycle types — the single `Session` namespace for the sessions subject. */

import type { Identities } from '../identities'

/**
 * Authenticated (or guest, or API-key) bearer of access. Issued by the configured
 * Transport; resolved on every authed request. AAL + factor model follows NIST 800-63B.
 */
export const AUTH_SESSION_KINDS = ['guest', 'user', 'apikey'] as const

export const AUTH_SESSION_FACTOR_METHODS = [
  'password',
  'passkey',
  'totp',
  'oauth',
  'magic-link',
  'webauthn',
  'sms',
  'api-key',
  'backup-code',
] as const

export namespace Sessions {
  /** NIST 800-63B Authentication Assurance Levels. */
  export type AAL = 1 | 2 | 3

  export type FactorMethod = (typeof AUTH_SESSION_FACTOR_METHODS)[number]

  export interface Factor {
    method: FactorMethod
    completedAt: Date
  }

  export type Kind = (typeof AUTH_SESSION_KINDS)[number]

  /** Audit-visible impersonation envelope; absent on non-impersonation sessions. */
  export type ActingAs = {
    realIdentityId: string
    startedAt: Date
    reason: string
    expiresAt: Date
  }

  export type Me = {
    id: string
    identityId: string | null
    tenantId: string | null
    kind: Kind
    aal: AAL
    factors: Factor[]
    /** Per-session CSRF token hash (sha-256). Cookie carries the plaintext under __Host-. */
    csrfHash: string | null
    /** Captured at create; used by hijack-detection policy. */
    ip: string | null
    userAgent: string | null
    fingerprint: string | null
    createdAt: Date
    rotatedAt: Date
    expiresAt: Date
    absoluteExpiresAt: Date
    fresh: boolean
    actingAs: ActingAs | null
  }

  /**
   * Input to `Store.create`. Callers provide the identifying + lifecycle
   * fields; every nullable column is explicit `T | null` — the facet
   * coalesces optional public inputs before passing this type.
   */
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
    getByHash(sidHash: string): Promise<Me | null>
    update(id: string, patch: Partial<Me>): Promise<Me>
    delete(id: string): Promise<void>
    listByIdentity(identityId: string): Promise<Me[]>
    deleteAllForIdentity(identityId: string): Promise<void>
    /** Periodic GC. Acquires distributed lease before running. */
    gc(now: number): Promise<{ deleted: number }>
  }

  /** SessionsFacet tuning. */
  export type Cfg = {
    /** Sliding TTL in ms. Default 7 days. */
    ttlMs: number
    /** Hard absolute cap in ms. Default 30 days. */
    absoluteTtlMs: number
    /** Window in ms where a session counts as "fresh" since the last factor. Default 5 min. */
    freshnessMs: number
  }

  /** Facet-level mint input to {@link SessionsFacet.create}; the facet coalesces these into a `CreateInput`. */
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
  }

  export interface RotateInput extends MintInput {
    /**
     * DESIGN section 37 rotation matrix. Drives whether the previous SID is revoked
     * outright, downgraded (step-up old-SID kept alive at lower AAL), or left
     * alone (impersonation start runs alongside the original session).
     */
    purpose:
      | 'signin'
      | 're-auth'
      | 'step-up'
      | 'step-down'
      | 'credential-change'
      | 'impersonate-start'
      | 'impersonate-release'
      | 'guest-promotion'
    previousSid?: string
  }
}
