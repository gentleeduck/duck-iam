import type { TenantContext } from '~/core/tenant/tenant.types'

/** Apps not using orgs leave `Org = never`, and the tree-shaker drops the facet. */
export namespace Org {
  /** An org. */
  export type Me<Meta = unknown> = {
    id: string
    name: string
    domain: string | null
    metadata: Meta | null
    createdAt: Date
    /** The tenant this row belongs to, `null` for a global one. Required so the facet can check the row
     *  it got back against the scope it asked for; without it `ctx` was a promise no caller could audit. */
    tenantId: string | null
  }

  /** An identity's place in an org, and its roles there. */
  export type Membership = {
    identityId: string
    orgId: string
    /** Org-scoped roles, distinct from tenant-wide identity roles. */
    roles: string[]
    invitedAt: Date | null
    joinedAt: Date
    leftAt: Date | null
    /** As {@link Org.Me.tenantId}. */
    tenantId: string | null
  }

  /** Every method takes the context and every row answers with the tenant it was read under, so the
   *  facet refuses a row from another one rather than trusting the store filtered. A single-tenant host
   *  passes `{}` and writes `tenantId: null`. */
  export type Store<Meta = unknown> = {
    /** The org with this id; raises when there is none. */
    getOrg(id: string, ctx: TenantContext): Promise<Me<Meta>>
    /** The orgs the identity is a live member of. An org row carries no membership, so this filter is the
     *  store's alone. */
    listOrgsForIdentity(identityId: string, ctx: TenantContext): Promise<Me<Meta>[]>
    /** Live rows or every row; the facet drops any marked `leftAt`. */
    listMembers(orgId: string, ctx: TenantContext): Promise<Membership[]>
    /** Adds a member, stamping `joinedAt`. */
    addMember(m: Omit<Membership, 'joinedAt'>, ctx: TenantContext): Promise<Membership>
    /** Both answer the membership they touched, `removeMember` the row as it stands left and `setRoles` the
     *  row carrying its new roles. No such membership raises, as every other store's miss does; a caller
     *  wanting absence as a value asks for `orNull()`. */
    removeMember(orgId: string, identityId: string, ctx: TenantContext): Promise<Membership>
    /** Replaces the member's roles. */
    setRoles(orgId: string, identityId: string, roles: string[], ctx: TenantContext): Promise<Membership>
  }
}
