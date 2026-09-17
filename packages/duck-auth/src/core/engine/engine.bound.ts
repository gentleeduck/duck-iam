import { ApiKeysFacet } from '~/providers/api-key'
import { MfaFacet } from '~/providers/mfa'
import { PasswordsImpl } from '~/providers/passwords'
import { AuthError } from '../errors'
import type { Events } from '../events'
import type { FlowsImpl } from '../flows'
import { type Identities, IdentitiesImpl } from '../identities'
import { OrgsImpl } from '../orgs'
import { createPending, type Pending } from '../pending'
import type { Providers } from '../provider'
import type { Sessions } from '../sessions'
import { SessionsImpl } from '../sessions'
import type { Engine } from './engine.types'

/** The transaction-bound view of an `AuthEngine`: layer-3 writes only. */
export namespace Bound {
  /**
   * Everything on this facade runs on the client passed to `withTransaction`,
   * and every event it would have emitted lands in {@link AuthEngine.pending}
   * instead.
   *
   * `limiter`, `idempotency`, `hijack`, `anomaly`, `captcha`, `transport`,
   * `plugins` and `resolveSession` are deliberately absent: they are
   * request-scoped guards that write nothing to SQL, so a rollback has nothing
   * to undo and joining a transaction would be meaningless. Reach them on the
   * engine itself.
   */
  export interface AuthEngine<Profile extends Identities.ProfileMetadataBase, OrgMeta> {
    readonly identities: IdentitiesImpl<Profile>
    readonly sessions: SessionsImpl
    readonly orgs: OrgsImpl<OrgMeta> | null
    readonly flows: FlowsImpl<Profile>
    /**
     * Resolved from the bound registry, exactly as the engine's own getters
     * resolve from its registry. Throws `AUTH_PROVIDER_NOT_REGISTERED` when the
     * corresponding provider was never added - same as on the engine.
     */
    readonly mfa: MfaFacet
    readonly apiKeys: ApiKeysFacet
    readonly passwords: PasswordsImpl
    readonly providers: Providers<Profile>
    readonly stores: Engine.Stores<Profile, OrgMeta>
    readonly pending: Pending.Effects
  }
}

/**
 * Re-bind the whole bag onto `client`, or throw. One call, because the facets come off one adapter and share
 * its connection; a hand-built mix has no `withClient`, and leaving a facet on the engine's own connection
 * would reintroduce exactly the partial-write bug this facade exists to remove.
 */
export function rebindStores<S extends { withClient?(client: unknown): S }>(stores: S, client: unknown): S {
  const rebind = stores.withClient
  if (!rebind) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail:
        'withTransaction: these stores cannot join a transaction (no withClient). Pass an adapter that ' +
        'has one as `stores`, or perform this write outside the transaction.',
    })
  }
  return rebind.call(stores, client)
}

/** Build the transaction-bound facade. Pure construction - no I/O. */
export function buildBoundEngine<Profile extends Identities.ProfileMetadataBase, OrgMeta>(args: {
  client: unknown
  stores: Engine.Stores<Profile, OrgMeta>
  events: Events.IBus
  identitiesCfg: Identities.Cfg
  sessionsCfg: Sessions.Cfg
  /**
   * The provider registry to hand the bound flows, built on the bound stores so registered facets - which
   * capture a store rather than reading it off the context - bind too.
   */
  buildProviders: (bus: Events.IBus, stores: Engine.Stores<Profile, OrgMeta>) => Providers<Profile>
  buildFlows: (deps: {
    sessions: SessionsImpl
    identities: IdentitiesImpl<Profile>
    providers: Providers<Profile>
    events: Events.IBus
    stores: Engine.Stores<Profile, OrgMeta>
  }) => FlowsImpl<Profile>
}): Bound.AuthEngine<Profile, OrgMeta> {
  const stores = rebindStores(args.stores, args.client)

  const { bus, pending } = createPending(args.events)

  const identities = new IdentitiesImpl<Profile>(stores.identities, bus, args.identitiesCfg, stores.credentials)
  const sessions = new SessionsImpl(stores.sessions, bus, args.sessionsCfg)
  const orgs = stores.orgs ? new OrgsImpl<OrgMeta>(stores.orgs, bus) : null
  const providers = args.buildProviders(bus, stores)
  const flows = args.buildFlows({ events: bus, identities, providers, sessions, stores })

  const resolveFacet = <T>(ctor: new (...a: never[]) => T, name: string): T => {
    const facet = providers.resolve(ctor)
    if (!facet) {
      throw new AuthError('AUTH_PROVIDER_NOT_REGISTERED', {
        detail: `this operation needs the '${name}' provider; add ${name}Provider() to providers[]`,
      })
    }
    return facet
  }

  return {
    flows,
    identities,
    orgs,
    pending,
    providers,
    sessions,
    stores,
    // Lazy, so a facade built without the mfa provider is still usable for
    // identities and sessions - matching how the engine's own getters behave.
    get mfa() {
      return resolveFacet(MfaFacet, 'mfa')
    },
    get apiKeys() {
      return resolveFacet(ApiKeysFacet, 'api-key')
    },
    get passwords() {
      return resolveFacet(PasswordsImpl, 'password')
    },
  }
}
