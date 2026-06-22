import type { AuthTenantContext } from './context'

/**
 * Organizations + membership. Locked to core in v4.2 (Q1 decision).
 * Apps not using orgs leave the generic `AuthOrg = never`; tree-shaker drops the facet.
 */
export namespace AuthOrg {
  export interface IOrg<Meta = unknown> {
    id: string
    name: string
    domain?: string
    metadata?: Meta
    createdAt: number
  }

  export interface IMembership {
    identityId: string
    orgId: string
    /** AuthOrg-scoped roles, distinct from tenant-wide identity roles. */
    roles: string[]
    invitedAt?: number
    joinedAt: number
    leftAt?: number
  }

  export interface IStore<Meta = unknown> {
    getOrg(id: string, ctx: AuthTenantContext): Promise<IOrg<Meta> | null>
    listOrgsForIdentity(identityId: string, ctx: AuthTenantContext): Promise<IOrg<Meta>[]>
    listMembers(orgId: string, ctx: AuthTenantContext): Promise<IMembership[]>
    addMember(m: Omit<IMembership, 'joinedAt'>, ctx: AuthTenantContext): Promise<IMembership>
    removeMember(orgId: string, identityId: string, ctx: AuthTenantContext): Promise<void>
    setRoles(orgId: string, identityId: string, roles: string[], ctx: AuthTenantContext): Promise<void>
  }
}
