import { isRevoked } from '~/core/credentials/credentials'
import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import type { TenantContext } from '~/core/tenant/tenant.types'
import type { Flows } from './flows.types'

function isProviderIdSafe(providerId: unknown): providerId is string {
  return typeof providerId === 'string' && providerId.length > 0 && providerId.length <= 128
}

/**
 * What still authenticates this identity if the given provider goes away.
 *
 * A provider link and a live password or passkey are interchangeable here:
 * either one is a way back in. Revoked credentials are not, and neither are
 * `recovery` rows - a reset token is a way to *replace* a factor, not a factor.
 */
async function remainingFactors<Profile extends Identities.ProfileMetadataBase>(
  identity: Identities.Me<Profile>,
  providerId: string,
  ctx: Provider.Context<Profile>,
  tenant: TenantContext,
): Promise<number> {
  const otherLinks = identity.providers.filter((p) => p.providerId !== providerId)
  const credentials = await ctx.stores.credentials.listByIdentity(identity.id, null, tenant)
  const liveCredentials = credentials.filter((c) => !isRevoked(c) && (c.kind === 'password' || c.kind === 'passkey'))
  return otherLinks.length + liveCredentials.length
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
      providerId: opts.providerId,
      detail: 'invalid providerSub',
    })
  }
  // A missing callback is a wiring mistake, not a failed link, so it reports as
  // one - the same treatment `cancelAccountDeletion` gives the same omission.
  if (typeof opts.authorize !== 'function') {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'linkProvider: an authorize({ identity, providerId, providerSub }) callback is required',
    })
  }
  // One context, reused. This function used to build two and `unlinkProvider`
  // three, each a fresh object graph over the same stores for no reason.
  const ctx = deps.ctxFactory(opts.tenantId)
  const identity = await deps.identities.getById(opts.identityId)
  if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')

  // Before the lookup and before the write. `providerSub` is an unverifiable
  // string as far as this library is concerned; this is the host asserting it
  // came from a dance they completed. A refusal reports as a provider failure
  // rather than a distinct code, so it is not a way to ask which subs are free.
  if (!(await opts.authorize({ identity, providerId: opts.providerId, providerSub: opts.providerSub }))) {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: opts.providerId,
      detail: 'authorize() returned false',
    })
  }

  const existing = await ctx.stores.identities.findByProviderSub(opts.providerId, opts.providerSub)
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

  const linked = await ctx.stores.identities.link(opts.identityId, {
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
  const ctx = deps.ctxFactory(opts.tenantId)
  const identity = await deps.identities.getById(opts.identityId)
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

  const unlinked = await ctx.stores.identities.unlink(opts.identityId, opts.providerId)
  if (!unlinked) throw new AuthError('AUTH_UNAUTHENTICATED')

  // The guard above is a read followed by a write, and `Identities.Store.unlink`
  // takes no expected version, so nothing serialises two of these against each
  // other. Two concurrent unlinks of *different* providers each saw the other's
  // link still present, each concluded a factor would survive, and both landed:
  // an identity with no way back in, produced by a guard whose entire job was to
  // prevent that.
  //
  // Re-asking the question after the write is what closes it. The loser of the
  // race now sees the post-write truth and puts its link back, restoring the
  // original `addedAt` so the row is the one it removed rather than a new one.
  // Both racers rolling back is possible and is the safe direction: the caller
  // gets a refusal and the account keeps both factors. A real transaction would
  // do better, and needs a store interface that can express one.
  if (!opts.allowLockout && (await remainingFactors(unlinked, opts.providerId, ctx, tenant)) === 0) {
    for (const link of linked) {
      await ctx.stores.identities.link(opts.identityId, link)
    }
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: opts.providerId,
      detail: 'refusing to unlink the only authentication factor; pass allowLockout:true to override',
    })
  }

  // The mirror of `identity.linked`, which linking has always emitted. Dropping
  // an authentication factor left no trace at all - the write an account
  // takeover performs to close the real owner's way back in was the one write
  // the audit log could not see.
  await deps.events.emit('identity.unlinked', {
    allowedLockout: opts.allowLockout === true,
    identityId: opts.identityId,
    providerId: opts.providerId,
  })
  return { identity: unlinked, identityId: opts.identityId, providerId: opts.providerId }
}
