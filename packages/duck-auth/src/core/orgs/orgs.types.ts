import type { TenantContext } from '~/core/types/infra'

/**
 * Organizations + membership. Locked to core in v4.2 (Q1 decision).
 * Apps not using orgs leave the generic `Org = never`; tree-shaker drops the facet.
 */
export namespace Org {
  export type Me<Meta = unknown> = {
    id: string
    name: string
    domain: string | null
    metadata: Meta | null
    createdAt: Date
  }

  export type Membership = {
    identityId: string
    orgId: string
    /** Org-scoped roles, distinct from tenant-wide identity roles. */
    roles: string[]
    invitedAt: Date | null
    joinedAt: Date
    leftAt: Date | null
  }

  export type Store<Meta = unknown> = {
    getOrg(id: string, ctx: TenantContext): Promise<Me<Meta> | null>
    listOrgsForIdentity(identityId: string, ctx: TenantContext): Promise<Me<Meta>[]>
    listMembers(orgId: string, ctx: TenantContext): Promise<Membership[]>
    addMember(m: Omit<Membership, 'joinedAt'>, ctx: TenantContext): Promise<Membership>
    removeMember(orgId: string, identityId: string, ctx: TenantContext): Promise<void>
    setRoles(orgId: string, identityId: string, roles: string[], ctx: TenantContext): Promise<void>
  }
}
