/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { TenantContext } from './context'

/**
 * Organizations + membership. Locked to core in v4.2 (Q1 decision).
 * Apps not using orgs leave the generic `Org = never`; tree-shaker drops the facet.
 */
export namespace Org {
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
    /** Org-scoped roles, distinct from tenant-wide identity roles. */
    roles: string[]
    invitedAt?: number
    joinedAt: number
    leftAt?: number
  }

  export interface IStore<Meta = unknown> {
    getOrg(id: string, ctx: TenantContext): Promise<IOrg<Meta> | null>
    listOrgsForIdentity(identityId: string, ctx: TenantContext): Promise<IOrg<Meta>[]>
    listMembers(orgId: string, ctx: TenantContext): Promise<IMembership[]>
    addMember(m: Omit<IMembership, 'joinedAt'>, ctx: TenantContext): Promise<IMembership>
    removeMember(orgId: string, identityId: string, ctx: TenantContext): Promise<void>
    setRoles(orgId: string, identityId: string, roles: string[], ctx: TenantContext): Promise<void>
  }
}
