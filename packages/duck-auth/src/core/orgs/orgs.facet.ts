import type { Events } from '~/core/events/events.types'
import { AuthError } from '../errors'
import type { TenantContext } from '../tenant/tenant.types'
import type { Org } from './orgs.types'

/**
 * Orgs + Membership facet. Locked to core in v4.2 (Q1 decision). Apps
 * without org concept leave the generic `OrgMeta = never` and the facet
 * tree-shakes to zero references.
 *
 * Iam pairing: each membership carries org-scoped roles distinct from
 * tenant-wide identity roles. Apps that pair iam project an identity x
 * org pair into a Subject whose `roles` come from `Membership.roles`.
 * The library exposes the contract; the projection lives in app code.
 */
export class OrgsFacet<OrgMeta = unknown> {
  constructor(
    private readonly _store: Org.Store<OrgMeta>,
    readonly _events: Events.IBus,
  ) {}

  /** Get an org by id. */
  async get(id: string, ctx: TenantContext = {}): Promise<Org.Me<OrgMeta> | null> {
    return this._store.getOrg(id, ctx)
  }

  /** List the orgs an identity belongs to. */
  async listForIdentity(identityId: string, ctx: TenantContext = {}): Promise<Org.Me<OrgMeta>[]> {
    return this._store.listOrgsForIdentity(identityId, ctx)
  }

  /** List the memberships of an org. */
  async listMembers(orgId: string, ctx: TenantContext = {}): Promise<Org.Membership[]> {
    return this._store.listMembers(orgId, ctx)
  }

  /**
   * Add a member with starting roles. Idempotent in spirit - adding the same
   * identity to the same org twice is allowed if the previous membership
   * has been marked `leftAt`. Otherwise surfaces a generic provider error.
   */
  async addMember(
    input: { orgId: string; identityId: string; roles?: string[] },
    ctx: TenantContext = {},
  ): Promise<Org.Membership> {
    const existing = await this._store.listMembers(input.orgId, ctx)
    const live = existing.find((m) => m.identityId === input.identityId && !m.leftAt)
    if (live) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: 'orgs',
        detail: 'identity already a member of this org',
      })
    }
    const m = await this._store.addMember(
      {
        orgId: input.orgId,
        identityId: input.identityId,
        roles: sanitizeRoles(input.roles),
        invitedAt: null,
        leftAt: null,
      },
      ctx,
    )
    return m
  }

  /** Remove (mark leftAt) a membership. Idempotent. */
  async removeMember(orgId: string, identityId: string, ctx: TenantContext = {}): Promise<void> {
    await this._store.removeMember(orgId, identityId, ctx)
  }

  /** Replace the role set for a member. */
  async setRoles(orgId: string, identityId: string, roles: string[], ctx: TenantContext = {}): Promise<void> {
    await this._store.setRoles(orgId, identityId, sanitizeRoles(roles), ctx)
  }

  /**
   * Resolve the membership of (identity, org) for the in-tenant scope.
   * Returns null when the identity is not a live member.
   */
  async resolveMembership(orgId: string, identityId: string, ctx: TenantContext = {}): Promise<Org.Membership | null> {
    const members = await this._store.listMembers(orgId, ctx)
    return members.find((m) => m.identityId === identityId && !m.leftAt) ?? null
  }
}

/** Bounds for `roles: string[]` on `addMember` + `setRoles`; silent per-entry filter, no throw. */
const ROLES_MAX_COUNT = 64
const ROLE_MAX_LENGTH = 128

function sanitizeRoles(raw: unknown): string[] {
  if (!Array.isArray(raw)) return []
  const out: string[] = []
  for (const r of raw) {
    if (typeof r !== 'string') continue
    if (r.length === 0 || r.length > ROLE_MAX_LENGTH) continue
    out.push(r)
    if (out.length >= ROLES_MAX_COUNT) break
  }
  return out
}
