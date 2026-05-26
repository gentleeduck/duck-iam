/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

/**
 * Authenticated (or guest, or API-key) bearer of access. Issued by the configured
 * Transport; resolved on every authed request. AAL + factor model follows NIST 800-63B.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace Session {
  /** NIST 800-63B Authentication Assurance Levels. */
  export type AAL = 1 | 2 | 3

  export type FactorMethod =
    | 'password'
    | 'passkey'
    | 'totp'
    | 'oauth'
    | 'magic-link'
    | 'webauthn'
    | 'sms'
    | 'api-key'
    | 'backup-code'

  export interface Factor {
    method: FactorMethod
    completedAt: number
  }

  export type Kind = 'guest' | 'user' | 'apikey'

  /** Audit-visible impersonation envelope; absent on non-impersonation sessions. */
  export interface ActingAs {
    realIdentityId: string
    startedAt: number
    reason: string
    expiresAt: number
  }

  export interface ISession {
    id: string
    identityId: string | null
    tenantId?: string
    kind: Kind
    aal: AAL
    factors: Factor[]
    /** Per-session CSRF token hash (sha-256). Cookie carries the plaintext under __Host-. */
    csrfHash?: string
    /** Captured at create; used by hijack-detection policy. */
    ip?: string
    userAgent?: string
    fingerprint?: string
    createdAt: number
    rotatedAt: number
    expiresAt: number
    absoluteExpiresAt: number
    fresh: boolean
    actingAs?: ActingAs
  }

  export interface IStore {
    create(s: ISession): Promise<void>
    getByHash(sidHash: string): Promise<ISession | null>
    update(id: string, patch: Partial<ISession>): Promise<ISession>
    delete(id: string): Promise<void>
    listByIdentity(identityId: string): Promise<ISession[]>
    deleteAllForIdentity(identityId: string): Promise<void>
    /** Periodic GC. Acquires distributed lease before running. */
    gc(now: number): Promise<{ deleted: number }>
  }
}
