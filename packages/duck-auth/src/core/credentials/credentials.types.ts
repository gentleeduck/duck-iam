import type { TenantContext } from '../tenant/tenant.types'
import type { AUTH_CREDENTIAL_KINDS } from './credentials.constants'

/** The credential row, its kinds and purposes, and the store contract over it. */
export namespace Credential {
  export type Kind = (typeof AUTH_CREDENTIAL_KINDS)[number]

  export type Me = {
    id: string
    identityId: string
    /** `null` is a global row, which a tenant-scoped read does not see. */
    tenantId: string | null
    /** What the secret is, and what every read and delete filters on besides the owner. */
    kind: Kind
    /** The stored secret: a hash, a passkey public key, or a totp seed. Use {@link Public} to hand a row out. */
    secret: string
    /** Absent metadata is `null`, never `undefined`. */
    metadata: Record<string, unknown> | null
    /** Optimistic-concurrency counter; a single-use claim burns the row by passing it as `expectedVersion`. */
    version: number
    createdAt: Date
    /** Moves on every write to the row. SQL maintains it through `$onUpdate`; the memory store stamps it. */
    updatedAt: Date
    /** Absent until the credential is first presented. */
    lastUsedAt: Date | null
    /** `null` means it does not expire of its own accord. */
    expiresAt: Date | null
    /** Set once revoked; the row is kept, so a replay is refused rather than missed. */
    revokedAt: Date | null
    /** The actor the create was attributed to, or `null` where none was bound. */
    createdBy: string | null
    /** The actor the last write was attributed to, or `null` where none was bound. */
    updatedBy: string | null
  }

  export type Public = Omit<Me, 'secret'>

  /** The store stamps `id`, `version` and `createdAt`; see {@link Credential.Store.create}. */
  export type CreateInput = {
    identityId: string
    kind: Kind
    secret: string
    tenantId: string | null
    metadata: Record<string, unknown> | null
    lastUsedAt: Date | null
    expiresAt: Date | null
    revokedAt: Date | null
  }

  /** Throws on failure, absence included: no row raises `AUTH_CREDENTIAL_NOT_FOUND`. The facet holding this
   *  store is where absence becomes a value. The list forms are the exception: zero rows is a list, not an
   *  absence. */
  export type Store = {
    findById(id: string, ctx: TenantContext): Promise<Me>
    listByIdentity(identityId: string, kind: Kind | null, ctx: TenantContext): Promise<Me[]>
    /** The freshest live row, falling back to a revoked one. */
    findByHashedSecret(secretHash: string, kind: Kind, ctx: TenantContext): Promise<Me>
    create(input: CreateInput, ctx: TenantContext): Promise<Me>
    rotate(id: string, newSecret: string, expectedVersion: number, ctx: TenantContext): Promise<Me>
    /** Shallow-merges `patch` into `metadata` and bumps the version. Given `expectedVersion` it is a
     *  compare-and-set: a row that moved first rejects `AUTH_STALE_WRITE` and nothing is written, which
     *  is how a caller makes "read a value, decide, record the new one" a single atomic step. */
    patchMetadata(id: string, patch: Record<string, unknown>, ctx: TenantContext, expectedVersion?: number): Promise<Me>
    /** Every removal below answers the row it removed. */
    revoke(id: string, ctx: TenantContext): Promise<Me>
    /** Every live `oauth` row sharing `metadata.familyId`, answering how many moved. */
    revokeFamily(familyId: string, ctx: TenantContext): Promise<number>
    delete(id: string, ctx: TenantContext): Promise<Me>
    deleteByKind(identityId: string, kind: Kind, ctx: TenantContext): Promise<Me[]>
    /** `deleteByKind` narrowed to one `metadata.purpose`, in one round trip. */
    deleteByKindAndPurpose(identityId: string, kind: Kind, purpose: string, ctx: TenantContext): Promise<Me[]>
  }
}
