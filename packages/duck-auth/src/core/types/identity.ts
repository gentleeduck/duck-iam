/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { TenantContext } from './context'

/**
 * Stable identity record. Opaque to the auth core - application-specific shape
 * carried in `profile`. The iam-auth-bridge projects this into Subject for
 * iam evaluation; non-iam apps leave the bridge unwired and pay zero coupling.
 */
export namespace Identity {
  export interface ProviderLink {
    providerId: string
    providerSub?: string
    addedAt: number
  }

  export interface IIdentity<Profile = unknown> {
    id: string
    tenantId?: string
    profile?: Profile
    providers: ProviderLink[]
    /** Optimistic-locking version. Incremented on every successful write. */
    version: number
    createdAt: number
    updatedAt: number
    /** Soft-delete grace; identity hidden from queries when set, hard-purged after window. */
    deletedAt?: number
  }

  export interface IStore<Profile = unknown> {
    findById(id: string, ctx: TenantContext): Promise<IIdentity<Profile> | null>
    findByEmail(email: string, ctx: TenantContext): Promise<IIdentity<Profile> | null>
    findByProviderSub(providerId: string, sub: string, ctx: TenantContext): Promise<IIdentity<Profile> | null>
    create(
      input: Omit<IIdentity<Profile>, 'id' | 'version' | 'createdAt' | 'updatedAt'>,
      ctx: TenantContext,
    ): Promise<IIdentity<Profile>>
    update(
      id: string,
      patch: Partial<IIdentity<Profile>>,
      expectedVersion: number,
      ctx: TenantContext,
    ): Promise<IIdentity<Profile>>
    softDelete(id: string, gracePeriodMs: number, ctx: TenantContext): Promise<void>
    restore(id: string, ctx: TenantContext): Promise<IIdentity<Profile>>
    erase(id: string, ctx: TenantContext): Promise<void>
    link(identityId: string, link: ProviderLink, ctx: TenantContext): Promise<void>
    unlink(identityId: string, providerId: string, ctx: TenantContext): Promise<void>
    merge(survivorId: string, dupId: string, ctx: TenantContext): Promise<void>
  }
}
