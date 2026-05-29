import { isRevoked } from '../../credential-utils'
import { AuthErrorObject } from '../../errors'
import type { TenantContext } from '../../types/context'
import type { FlowsFacet } from '../flows'

function isProviderIdSafe(providerId: unknown): providerId is string {
  return typeof providerId === 'string' && providerId.length > 0 && providerId.length <= 128
}

export async function linkProvider<Profile>(
  flows: FlowsFacet<Profile>,
  opts: FlowsFacet.ILinkProviderInput,
): Promise<{ identityId: string; providerId: string }> {
  if (!isProviderIdSafe(opts.providerId)) {
    throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
      providerId: 'invalid',
      detail: 'invalid providerId',
    })
  }
  if (typeof opts.providerSub !== 'string' || opts.providerSub.length === 0 || opts.providerSub.length > 512) {
    throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
      providerId: opts.providerId,
      detail: 'invalid providerSub',
    })
  }
  const tenant: TenantContext = opts.tenantId !== undefined ? { tenantId: opts.tenantId } : {}
  const identity = await flows._identities.getById(opts.identityId, tenant)
  if (!identity) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')

  const existing = await flows
    ._ctxFactory(opts.tenantId)
    .stores.identities.findByProviderSub(opts.providerId, opts.providerSub, tenant)
  if (existing && existing.id !== opts.identityId) {
    throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
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

  await flows
    ._ctxFactory(opts.tenantId)
    .stores.identities.link(
      opts.identityId,
      { providerId: opts.providerId, providerSub: opts.providerSub, addedAt: Date.now() },
      tenant,
    )
  await flows._events.emit('identity.linked', {
    identityId: opts.identityId,
    providerId: opts.providerId,
  })
  return { identityId: opts.identityId, providerId: opts.providerId }
}

export async function unlinkProvider<Profile>(
  flows: FlowsFacet<Profile>,
  opts: FlowsFacet.IUnlinkProviderInput,
): Promise<{ identityId: string; providerId: string }> {
  if (!isProviderIdSafe(opts.providerId)) {
    throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
      providerId: 'invalid',
      detail: 'invalid providerId',
    })
  }
  const tenant: TenantContext = opts.tenantId !== undefined ? { tenantId: opts.tenantId } : {}
  const identity = await flows._identities.getById(opts.identityId, tenant)
  if (!identity) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')

  const linked = identity.providers.filter((p) => p.providerId === opts.providerId)
  if (linked.length === 0) {
    return { identityId: opts.identityId, providerId: opts.providerId }
  }

  if (!opts.allowLockout) {
    const otherLinks = identity.providers.filter((p) => p.providerId !== opts.providerId)
    const ctx = flows._ctxFactory(opts.tenantId)
    const credentials = await ctx.stores.credentials.listByIdentity(opts.identityId, undefined, tenant)
    const liveCredentials = credentials.filter((c) => !isRevoked(c) && (c.kind === 'password' || c.kind === 'passkey'))
    if (otherLinks.length === 0 && liveCredentials.length === 0) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId: opts.providerId,
        detail: 'refusing to unlink the only authentication factor; pass allowLockout:true to override',
      })
    }
  }

  await flows._ctxFactory(opts.tenantId).stores.identities.unlink(opts.identityId, opts.providerId, tenant)
  return { identityId: opts.identityId, providerId: opts.providerId }
}
