import { isRevoked } from '~/core/credentials/credentials'
import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities'
import type { TenantContext } from '~/core/tenant/tenant.types'
import type { Flows } from './flows.types'

function isProviderIdSafe(providerId: unknown): providerId is string {
  return typeof providerId === 'string' && providerId.length > 0 && providerId.length <= 128
}

export async function linkProvider<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  opts: Flows.LinkProviderInput,
): Promise<{ identity: Identities.Me<Profile>; identityId: string; providerId: string }> {
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
    // Idempotent: nothing to write, and `identity` is already the row a caller
    // would get back from the write.
    return { identity, identityId: opts.identityId, providerId: opts.providerId }
  }

  const linked = await deps.ctxFactory(opts.tenantId).stores.identities.link(opts.identityId, {
    providerId: opts.providerId,
    providerSub: opts.providerSub,
    addedAt: new Date(),
  })
  // `null` means the row went between the read above and the write - the same
  // condition the read rejected, so it gets the same answer.
  if (!linked) throw new AuthError('AUTH_UNAUTHENTICATED')
  await deps.events.emit('identity.linked', {
    identityId: opts.identityId,
    providerId: opts.providerId,
  })
  return { identity: linked, identityId: opts.identityId, providerId: opts.providerId }
}

export async function unlinkProvider<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  opts: Flows.UnlinkProviderInput,
): Promise<{ identity: Identities.Me<Profile>; identityId: string; providerId: string }> {
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
    return { identity, identityId: opts.identityId, providerId: opts.providerId }
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

  const unlinked = await deps.ctxFactory(opts.tenantId).stores.identities.unlink(opts.identityId, opts.providerId)
  if (!unlinked) throw new AuthError('AUTH_UNAUTHENTICATED')
  return { identity: unlinked, identityId: opts.identityId, providerId: opts.providerId }
}
