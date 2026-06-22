import type { AuthTenantContext } from './context'

/**
 * Stable identity record. Opaque to the auth core - application-specific shape
 * carried in `profile`. The iam-auth-bridge projects this into Subject for
 * iam evaluation; non-iam apps leave the bridge unwired and pay zero coupling.
 */
export namespace AuthIdentity {
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
    findById(id: string, ctx: AuthTenantContext): Promise<IIdentity<Profile> | null>
    findByEmail(email: string, ctx: AuthTenantContext): Promise<IIdentity<Profile> | null>
    findByProviderSub(providerId: string, sub: string, ctx: AuthTenantContext): Promise<IIdentity<Profile> | null>
    create(
      input: Omit<IIdentity<Profile>, 'id' | 'version' | 'createdAt' | 'updatedAt'>,
      ctx: AuthTenantContext,
    ): Promise<IIdentity<Profile>>
    update(
      id: string,
      patch: Partial<IIdentity<Profile>>,
      expectedVersion: number,
      ctx: AuthTenantContext,
    ): Promise<IIdentity<Profile>>
    softDelete(id: string, gracePeriodMs: number, ctx: AuthTenantContext): Promise<void>
    restore(id: string, ctx: AuthTenantContext): Promise<IIdentity<Profile>>
    erase(id: string, ctx: AuthTenantContext): Promise<void>
    link(identityId: string, link: ProviderLink, ctx: AuthTenantContext): Promise<void>
    unlink(identityId: string, providerId: string, ctx: AuthTenantContext): Promise<void>
    merge(survivorId: string, dupId: string, ctx: AuthTenantContext): Promise<void>
  }
}
