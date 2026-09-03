import { describe, expect, it } from 'vitest'
import type { Batch, Credential, Events, Flows, Identities, Org, Pending, Sessions, TenantContext } from '~/index'
import * as root from '~/index'

/**
 * The root barrel used to export the engine and none of the types the engine
 * returns: you could call a method but not write down the type of what came
 * back without a second import from `@gentleduck/auth/core`.
 *
 * These are compile-time assertions. Each alias fails to typecheck if the type
 * stops being reachable from the root, which is the regression worth catching -
 * a barrel narrows silently and the break lands on the consumer.
 */
type _Identity = Identities.Me<Identities.ProfileMetadataBase>
type _Session = Sessions.Me
type _Credential = Credential.Me
type _Org = Org.Me
type _Batch = Batch.Result<_Identity>
type _Reason = Batch.FailureReason
type _Event = Events.EventName
type _Flow = Flows.Deps<Identities.ProfileMetadataBase>
type _Pending = Pending.Effects
type _Tenant = TenantContext

/** The return type of a real method, named without reaching into a subpath. */
type _Restored = Awaited<ReturnType<Identities.Store<Identities.ProfileMetadataBase>['restore']>>
const _restoredIsNullable: _Restored = null

describe('public surface', () => {
  it('the root barrel keeps its runtime exports', () => {
    // Runtime stays deliberately narrow; this pins it so widening is a choice.
    expect(Object.keys(root).sort()).toEqual([
      'AuthBearerTransport',
      'AuthCompositeTransport',
      'AuthCookieTransport',
      'AuthEngine',
      'AuthError',
      // The actor context is runtime, not just types: `withActor` is how a
      // caller fills `createdBy` / `updatedBy`, so it has to be reachable from
      // the root the same way the engine is.
      'actorId',
      'authEngine',
      'currentActor',
      'resolveActor',
      'rethrowAuthError',
      'setDefaultActorResolver',
      'throwAuthError',
      'withActor',
    ])
  })

  it('restore is typed as nullable, like softDelete and erase', () => {
    // `_restoredIsNullable` above does the real work at compile time; this keeps
    // the constant referenced so it cannot be dropped as dead code.
    expect(_restoredIsNullable).toBeNull()
  })
})
