import { type Answer, answer } from '~/core/answer'
import type { Events } from '~/core/events/events.types'
import { AuthError } from '../errors'
import type { TenantContext } from '../tenant/tenant.types'
import type { Org } from './orgs.types'

/** What both engines say when the orgs capability was never wired. It names `stores.orgs` rather than a
 *  provider, because there is no `orgsProvider()` to add. */
export const ORGS_NOT_CONFIGURED = 'this operation needs an org store; pass `stores.orgs` to createAuth()'

/** Apps with no org concept leave `OrgMeta = never`, and the facet tree-shakes to zero references. */
export class OrgsImpl<OrgMeta = unknown> {
  constructor(
    private readonly _store: Org.Store<OrgMeta>,
    /** WARN: nothing here emits. There is no `org.*` event in the bus's map, so membership and role
     *  changes - `setRoles` grants privileges - leave no audit trail, unlike every comparable
     *  operation (`mfa.enrolled`, `identity.linked`, `authz.revoked`). A host needing one wraps these
     *  methods for now; adding the events is a change to the public event map, not an audit fix. */
    readonly _events: Events.IBus,
  ) {}

  /** The org with this id. */
  get(id: string, ctx: TenantContext = {}): Answer.Me<Org.Me<OrgMeta>> {
    return answer(this._store.getOrg(id, ctx))
  }

  /** Every org this identity is a member of. */
  async listForIdentity(identityId: string, ctx: TenantContext = {}): Promise<Org.Me<OrgMeta>[]> {
    return this._store.listOrgsForIdentity(identityId, ctx)
  }

  /** Every membership in this org. */
  async listMembers(orgId: string, ctx: TenantContext = {}): Promise<Org.Membership[]> {
    return this._store.listMembers(orgId, ctx)
  }

  /** Re-adding an identity whose previous membership is marked `leftAt` is allowed; a live one is a
   *  conflict on (org, identity). */
  async addMember(
    input: { orgId: string; identityId: string; roles?: string[] },
    ctx: TenantContext = {},
  ): Promise<Org.Membership> {
    const existing = await this._store.listMembers(input.orgId, ctx)
    const live = existing.find((m) => m.identityId === input.identityId && !m.leftAt)
    if (live) {
      throw new AuthError('AUTH_ALREADY_EXISTS', { detail: 'identity already a member of this org' })
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

  /** Marks `leftAt`, answering the membership as it stands left. An identity that was not a member
   *  rejects; `orNull()` is how an idempotent caller reads that as having done nothing. */
  removeMember(orgId: string, identityId: string, ctx: TenantContext = {}): Answer.Me<Org.Membership> {
    return answer(this._store.removeMember(orgId, identityId, ctx))
  }

  /** Answers the membership carrying the sanitized set actually stored, not the one passed in.
   *  NOTE: the store decides whether a membership marked `leftAt` can still be given roles. The
   *  shipped memory store allows it, and the write is unreadable - `listMembers` and
   *  `resolveMembership` skip left rows, and re-adding overwrites the roles wholesale. */
  setRoles(orgId: string, identityId: string, roles: string[], ctx: TenantContext = {}): Answer.Me<Org.Membership> {
    return answer(this._store.setRoles(orgId, identityId, sanitizeRoles(roles), ctx))
  }

  /** Rejects `AUTH_MEMBERSHIP_NOT_FOUND` when the identity is not a live member. */
  resolveMembership(orgId: string, identityId: string, ctx: TenantContext = {}): Answer.Me<Org.Membership> {
    return answer(async () => {
      const members = await this._store.listMembers(orgId, ctx)
      const live = members.find((m) => m.identityId === identityId && !m.leftAt)
      if (!live) {
        throw new AuthError('AUTH_MEMBERSHIP_NOT_FOUND')
      }

      return live
    })
  }
}

function sanitizeRoles(raw: unknown): string[] {
  /** Bounds for `roles: string[]` on `addMember` + `setRoles`; silent per-entry filter, no throw. */
  const ROLES_MAX_COUNT = 64
  const ROLE_MAX_LENGTH = 128

  if (!Array.isArray(raw)) return []
  const out = new Set<string>()
  for (const r of raw) {
    if (typeof r !== 'string') continue
    if (r.length === 0 || r.length > ROLE_MAX_LENGTH) continue
    // Deduplicated before the cap is counted, or sixty-four copies of one role fill the budget and
    // silently drop the real grants behind them.
    out.add(r)
    if (out.size >= ROLES_MAX_COUNT) break
  }
  return [...out]
}

export function orgs<OrgMeta>(store: Org.Store<OrgMeta>, events: Events.IBus): OrgsImpl<OrgMeta> {
  return new OrgsImpl(store, events)
}
