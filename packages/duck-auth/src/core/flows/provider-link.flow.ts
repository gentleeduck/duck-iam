import { orNull } from '~/core/answer'
import { isStandingFactor } from '~/core/credentials/credentials'
import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities'
import { echoableProviderId } from '~/core/provider/provider.constants'
import type { Provider } from '~/core/provider/provider.types'
import type { TenantContext } from '~/core/tenant/tenant.types'
import type { Flows } from './flows.types'

function isProviderIdSafe(providerId: unknown): providerId is string {
  return typeof providerId === 'string' && providerId.length > 0 && providerId.length <= 128
}

/** What still authenticates this identity if the given provider goes away. */
async function remainingFactors<Profile extends Identities.ProfileMetadataBase>(
  identity: Identities.Me<Profile>,
  providerId: string,
  ctx: Provider.Context<Profile>,
  tenant: TenantContext,
): Promise<number> {
  const otherLinks = identity.providers.filter((p) => p.providerId !== providerId)
  const credentials = await ctx.stores.credentials.listByIdentity(identity.id, null, tenant)
  return otherLinks.length + credentials.filter(isStandingFactor).length
}

export async function linkProvider<Profile extends Identities.ProfileMetadataBase>(
  deps: Flows.Deps<Profile>,
  opts: Flows.LinkProviderInput<Profile>,
): Promise<{ identity: Identities.Me<Profile>; identityId: string; providerId: string }> {
  if (!isProviderIdSafe(opts.providerId)) {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: 'invalid',
      detail: 'invalid providerId',
    })
  }
  if (typeof opts.providerSub !== 'string' || opts.providerSub.length === 0 || opts.providerSub.length > 512) {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: echoableProviderId(opts.providerId),
      detail: 'invalid providerSub',
    })
  }
  // A missing callback is a wiring mistake, not a failed link, so it reports as one, the treatment
  // `cancelAccountDeletion` gives the same omission.
  if (typeof opts.authorize !== 'function') {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'linkProvider: an authorize({ identity, providerId, providerSub }) callback is required',
    })
  }
  // One context, reused: a second would be a fresh object graph over the same stores.
  const ctx = deps.ctxFactory(opts.tenantId)
  const identity = await deps.identities.getById(opts.identityId).orNull()
  if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')

  // Before the lookup and before the write. `providerSub` is an unverifiable
  // string as far as this library is concerned; this is the host asserting it
  // came from a dance they completed.
  if (!(await opts.authorize({ identity, providerId: opts.providerId, providerSub: opts.providerSub }))) {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: opts.providerId,
      detail: 'authorize() returned false',
    })
  }

  const existing = await orNull(
    ctx.stores.identities.find({ providerId: opts.providerId, providerSub: opts.providerSub }),
  )
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

  const linked = await orNull(
    ctx.stores.identities.link(opts.identityId, { providerId: opts.providerId, providerSub: opts.providerSub }),
  )
  // `null` means the row went between the read above and the write, the same condition the read
  // rejected, so it gets the same answer.
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
  const ctx = deps.ctxFactory(opts.tenantId)
  const identity = await deps.identities.getById(opts.identityId).orNull()
  if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')

  const linked = identity.providers.filter((p) => p.providerId === opts.providerId)
  if (linked.length === 0) {
    return { identity, identityId: opts.identityId, providerId: opts.providerId }
  }

  if (!opts.allowLockout && (await remainingFactors(identity, opts.providerId, ctx, tenant)) === 0) {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: opts.providerId,
      detail: 'refusing to unlink the only authentication factor; pass allowLockout:true to override',
    })
  }

  const unlinked = await orNull(ctx.stores.identities.unlink(opts.identityId, opts.providerId))
  if (!unlinked) throw new AuthError('AUTH_UNAUTHENTICATED')

  // WARN: read-then-write, and `Identities.Store.unlink` takes no expected version, so two concurrent
  // unlinks of different providers can each see the other's link and both land, locking the identity out.
  if (!opts.allowLockout && (await remainingFactors(unlinked, opts.providerId, ctx, tenant)) === 0) {
    for (const link of linked) {
      await ctx.stores.identities.link(opts.identityId, link)
    }
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: opts.providerId,
      detail: 'refusing to unlink the only authentication factor; pass allowLockout:true to override',
    })
  }

  // The mirror of `identity.linked`, which linking has always emitted. Dropping an authentication
  // factor left no trace at all, so the write an account takeover performs to close the real owner's
  // way back in was the one write the audit log could not see.
  await deps.events.emit('identity.unlinked', {
    allowedLockout: opts.allowLockout === true,
    identityId: opts.identityId,
    providerId: opts.providerId,
  })
  return { identity: unlinked, identityId: opts.identityId, providerId: opts.providerId }
}
