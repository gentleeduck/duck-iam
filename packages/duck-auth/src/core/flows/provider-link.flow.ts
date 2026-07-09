import { isRevoked } from '~/core/credential-utils'
import { AuthError } from '~/core/errors'
import type { Identity } from '~/core/types'
import type { TenantContext } from '~/core/types/infra'
import type { FlowsFacet } from '../flows.facet'

function isProviderIdSafe(providerId: unknown): providerId is string {
  return typeof providerId === 'string' && providerId.length > 0 && providerId.length <= 128
}

export async function linkProvider<Profile extends Identity.ProfileMetadataBase>(
  deps: FlowsFacet.Deps<Profile>,
  opts: FlowsFacet.LinkProviderInput,
): Promise<{ identityId: string; providerId: string }> {
  if (!isProviderIdSafe(opts.providerId)) {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: 'invalid',
      detail: 'invalid providerId',
    })
  }
  if (typeof opts.providerSub !== 'string' || opts.providerSub.length === 0 || opts.providerSub.length > 512) {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: opts.providerId,
      detail: 'invalid providerSub',
    })
  }
  const identity = await deps.identities.getById(opts.identityId)
  if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')

  const existing = await deps
    .ctxFactory(opts.tenantId)
    .stores.identities.findByProviderSub(opts.providerId, opts.providerSub)
  if (existing && existing.id !== opts.identityId) {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: opts.providerId,
      detail: 'provider sub already linked to a different identity',
    })
  }

  const alreadyLinked = identity.providers.some(
    (p) => p.providerId === opts.providerId && p.providerSub === opts.providerSub,
  )
  if (alreadyLinked) {
    return { identityId: opts.identityId, providerId: opts.providerId }
  }

  await deps.ctxFactory(opts.tenantId).stores.identities.link(opts.identityId, {
    providerId: opts.providerId,
    providerSub: opts.providerSub,
    addedAt: new Date(),
  })
  await deps.events.emit('identity.linked', {
    identityId: opts.identityId,
    providerId: opts.providerId,
  })
  return { identityId: opts.identityId, providerId: opts.providerId }
}

export async function unlinkProvider<Profile extends Identity.ProfileMetadataBase>(
  deps: FlowsFacet.Deps<Profile>,
  opts: FlowsFacet.UnlinkProviderInput,
): Promise<{ identityId: string; providerId: string }> {
  if (!isProviderIdSafe(opts.providerId)) {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: 'invalid',
      detail: 'invalid providerId',
    })
  }
  const tenant: TenantContext = opts.tenantId !== undefined ? { tenantId: opts.tenantId } : {}
  const identity = await deps.identities.getById(opts.identityId)
  if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')

  const linked = identity.providers.filter((p) => p.providerId === opts.providerId)
  if (linked.length === 0) {
    return { identityId: opts.identityId, providerId: opts.providerId }
  }

  if (!opts.allowLockout) {
    const otherLinks = identity.providers.filter((p) => p.providerId !== opts.providerId)
    const ctx = deps.ctxFactory(opts.tenantId)
    const credentials = await ctx.stores.credentials.listByIdentity(opts.identityId, null, tenant)
    const liveCredentials = credentials.filter((c) => !isRevoked(c) && (c.kind === 'password' || c.kind === 'passkey'))
    if (otherLinks.length === 0 && liveCredentials.length === 0) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: opts.providerId,
        detail: 'refusing to unlink the only authentication factor; pass allowLockout:true to override',
      })
    }
  }

  await deps.ctxFactory(opts.tenantId).stores.identities.unlink(opts.identityId, opts.providerId)
  return { identityId: opts.identityId, providerId: opts.providerId }
}
