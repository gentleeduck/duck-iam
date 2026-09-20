import { describe, expect, it } from 'vitest'
import type { AuthEngine, Credential, Events, Flows, Identities, Org, Pending, Sessions, TenantContext } from '~/index'
import * as root from '~/index'

/**
 * The root barrel used to export the engine and none of the types the engine
 * returns: you could call a method but not write down the type of what came
 * back without a second import from `@gentleduck/auth/core`.
 */
type _Identity = Identities.Me<Identities.ProfileMetadataBase>
type _Session = Sessions.Me
type _Credential = Credential.Me
type _Org = Org.Me
type _Event = Events.EventName
type _Flow = Flows.Deps<Identities.ProfileMetadataBase>
type _Pending = Pending.Effects
type _Tenant = TenantContext

/** The return type of a real method, named without reaching into a subpath. */
type _Restored = Awaited<ReturnType<Identities.Store<Identities.ProfileMetadataBase>['restore']>>
// Only assignable while `null` is outside `_Restored`, which is the contract this pins.
const _restoreIsNotNullable: null extends _Restored ? false : true = true

/**
 * No public method answers absence as a value. A caller wanting that asks for it with `orNull()`, which eats
 * the `ABSENT` codes alone - so a missing row, a refused argument and a store that is down stay three
 * answers rather than one.
 */
type NullAnswering<T> = {
  [K in keyof T]-?: T[K] extends (...args: never[]) => infer R ? (null extends Awaited<R> ? K : never) : never
}[keyof T]

/** The same question one level down, for the facets and store bags hanging off the engine. */
type Facets<T> = {
  [K in keyof T]-?: T[K] extends (...args: never[]) => unknown
    ? never
    : T[K] extends object
      ? `${K & string}.${NullAnswering<T[K]> & string}`
      : never
}[keyof T]

type Surface<T> = `${NullAnswering<T> & string}` | Facets<T>

/** The transaction facade, reached the way a caller reaches it rather than through a subpath import. */
type BoundEngine = ReturnType<AuthEngine['withTransaction']>

/**
 * The lookups that answer `null` on purpose. Both are **synchronous**, and `Answer.Me` is a promise, so
 * neither has anywhere to hang a reader. `providers.resolve` is the registry lookup the engine's own
 * capability getters are built on - the null is what they branch on to throw - and `transport.extract` says
 * the request carried no token, which `resolveSession` turns into `AUTH_SESSION_REVOKED`. Anything else
 * appearing here is a regression, not an entry to add.
 */
type DeliberatelyNullable = 'auth.providers.resolve' | 'auth.transport.extract' | 'tx.providers.resolve'

type AnswersNull = Exclude<`auth.${Surface<AuthEngine>}` | `tx.${Surface<BoundEngine>}`, DeliberatelyNullable>

/** Satisfiable only by `never`, so a failure prints every offender by name rather than `true`/`false`. */
type NoneOf<T extends never> = T
type _NoOffenders = NoneOf<AnswersNull>
const _noPublicMethodAnswersNull: [_NoOffenders] extends [never] ? true : false = true

describe('public surface', () => {
  it('the root barrel keeps its runtime exports', () => {
    // Runtime stays deliberately narrow; this pins it so widening is a choice.
    expect(Object.keys(root).sort()).toEqual([
      'ABSENT',
      'AuthBearerTransport',
      'AuthCompositeTransport',
      'AuthCookieTransport',
      'AuthEngine',
      'AuthError',
      // The actor context is runtime, not just types: `withActor` is how a
      // caller fills `createdBy` / `updatedBy`, so it has to be reachable from
      // the root the same way the engine is.
      'actorId',
      'answer',
      'authEngine',
      'currentActor',
      'orNull',
      'resolveActor',
      'rethrowAuthError',
      'setDefaultActorResolver',
      'throwAuthError',
      'withActor',
    ])
  })

  it('restore answers a row or throws, never null', () => {
    // The constant above does the real work at compile time; this keeps it referenced.
    expect(_restoreIsNotNullable).toBe(true)
  })

  it('no public method answers null', () => {
    // `AnswersNull` above does the real work at compile time; this keeps the constant referenced.
    expect(_noPublicMethodAnswersNull).toBe(true)
  })
})
