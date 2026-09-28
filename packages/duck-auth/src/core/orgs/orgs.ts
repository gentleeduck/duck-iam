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
    readonly _events: Events.IBus,
  ) {}

  /** The org with this id. */
  get(id: string, ctx: TenantContext): Answer.Me<Org.Me<OrgMeta>> {
    return answer(async () => inScope(await this._store.getOrg(id, ctx), ctx))
  }

  /** Every org this identity is a member of. */
  async listForIdentity(identityId: string, ctx: TenantContext): Promise<Org.Me<OrgMeta>[]> {
    return (await this._store.listOrgsForIdentity(identityId, ctx)).map((org) => inScope(org, ctx))
  }

  /** Every live membership in this org; a row the store answers marked `leftAt` is dropped. */
  async listMembers(orgId: string, ctx: TenantContext): Promise<Org.Membership[]> {
    return (await this._store.listMembers(orgId, ctx)).map((m) => inScope(m, ctx)).filter((m) => !m.leftAt)
  }

  /** Re-adding an identity whose previous membership is marked `leftAt` is allowed; a live one is a
   *  conflict on (org, identity). */
  async addMember(
    input: { orgId: string; identityId: string; roles?: string[] },
    ctx: TenantContext,
  ): Promise<Org.Membership> {
    if ((await this.listMembers(input.orgId, ctx)).some((m) => m.identityId === input.identityId)) {
      throw new AuthError('AUTH_ALREADY_EXISTS', { detail: 'identity already a member of this org' })
    }
    const m = inScope(
      await this._store.addMember(
        {
          orgId: input.orgId,
          identityId: input.identityId,
          roles: sanitizeRoles(input.roles),
          invitedAt: null,
          leftAt: null,
          tenantId: ctx.tenantId ?? null,
        },
        ctx,
      ),
      ctx,
    )
    await this._events.emit('org.member.added', { orgId: m.orgId, identityId: m.identityId, roles: m.roles })
    return m
  }

  /** Marks `leftAt`, answering the membership as it stands left. An identity that was not a member
   *  rejects; `orNull()` is how an idempotent caller reads that as having done nothing. */
  removeMember(orgId: string, identityId: string, ctx: TenantContext): Answer.Me<Org.Membership> {
    return answer(async () => {
      const m = inScope(await this._store.removeMember(orgId, identityId, ctx), ctx)
      await this._events.emit('org.member.removed', { orgId, identityId })
      return m
    })
  }

  /** Answers the membership carrying the sanitized set actually stored, not the one passed in.
   *  NOTE: the store decides whether a membership marked `leftAt` can still be given roles. The
   *  shipped memory store allows it, and the write is unreadable - `listMembers` and
   *  `resolveMembership` skip left rows, and re-adding overwrites the roles wholesale. */
  setRoles(orgId: string, identityId: string, roles: string[], ctx: TenantContext): Answer.Me<Org.Membership> {
    return answer(async () => {
      const m = inScope(await this._store.setRoles(orgId, identityId, sanitizeRoles(roles), ctx), ctx)
      await this._events.emit('org.roles.set', { orgId, identityId, roles: m.roles })
      return m
    })
  }

  /** Rejects `AUTH_MEMBERSHIP_NOT_FOUND` when the identity is not a live member. */
  resolveMembership(orgId: string, identityId: string, ctx: TenantContext): Answer.Me<Org.Membership> {
    return answer(async () => {
      const live = (await this.listMembers(orgId, ctx)).find((m) => m.identityId === identityId)
      if (!live) {
        throw new AuthError('AUTH_MEMBERSHIP_NOT_FOUND')
      }

      return live
    })
  }
}

/** SECURITY: a row from another tenant is refused rather than answered. `Org.Store` is the host's own
 *  read interface, so the scoping is theirs to perform - this is the library checking they did, which is
 *  what the context could not be audited for while the rows carried no tenant. A `ctx` naming no tenant
 *  asks for everything and accepts everything, exactly as `_inTenant` does. */
function inScope<T extends { tenantId: string | null }>(row: T, ctx: TenantContext): T {
  if (ctx.tenantId === undefined || row.tenantId === ctx.tenantId) return row
  throw new AuthError('AUTH_TENANT_SCOPE_VIOLATION', { asked: ctx.tenantId, got: row.tenantId })
}

/** Bounds `roles` on `addMember` and `setRoles`, dropping each bad entry rather than throwing. */
function sanitizeRoles(raw: unknown): string[] {
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
