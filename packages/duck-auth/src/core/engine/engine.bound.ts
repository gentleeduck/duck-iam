import { ApiKeysFacet } from '~/providers/api-key'
import { MfaFacet } from '~/providers/mfa'
import { PasswordsImpl } from '~/providers/passwords'
import type { Credential } from '../credentials/credentials.types'
import { AuthError } from '../errors'
import type { Events } from '../events'
import type { FlowsImpl } from '../flows'
import { type Identities, IdentitiesImpl } from '../identities'
import { OrgsImpl } from '../orgs'
import type { Org } from '../orgs/orgs.types'
import { createPending, type Pending } from '../pending'
import type { Providers } from '../provider'
import type { Sessions } from '../sessions'
import { SessionsImpl } from '../sessions'

/** The transaction-bound view of an `AuthEngine`: layer-3 writes only. */
export namespace Bound {
  export type Stores<Profile extends Identities.ProfileMetadataBase, OrgMeta> = {
    identities: Identities.Store<Profile>
    sessions: Sessions.Store
    credentials: Credential.Store
    orgs?: Org.Store<OrgMeta>
  }

  /**
   * Everything on this facade runs on the client passed to `withTransaction`,
   * and every event it would have emitted lands in {@link AuthEngine.pending}
   * instead.
   *
   * `limiter`, `idempotency`, `hijack`, `anomaly`, `transport`, `plugins` and
   * `resolveSession` are deliberately absent: they are request-scoped guards
   * that write nothing to SQL, so a rollback has nothing to undo and joining a
   * transaction would be meaningless. Reach them on the engine itself.
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
    readonly stores: Stores<Profile, OrgMeta>
    readonly pending: Pending.Effects
  }
}

/**
 * Re-bind one store, or throw naming it. A store with no `withClient` cannot
 * join the transaction, and silently leaving it on the engine's own connection
 * would reintroduce exactly the partial-write bug this facade exists to remove.
 */
export function rebindStore<S extends { withClient?(client: unknown): S }>(store: S, client: unknown, name: string): S {
  const rebind = store.withClient
  if (!rebind) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail:
        `withTransaction: the '${name}' store cannot join a transaction (no withClient). ` +
        `Use a SQL adapter for '${name}', or perform this write outside the transaction.`,
    })
  }
  return rebind.call(store, client)
}

/** Build the transaction-bound facade. Pure construction - no I/O. */
export function buildBoundEngine<Profile extends Identities.ProfileMetadataBase, OrgMeta>(args: {
  client: unknown
  stores: Bound.Stores<Profile, OrgMeta>
  events: Events.IBus
  identitiesCfg: Identities.Cfg
  sessionsCfg: Sessions.Cfg
  /**
   * The provider registry to hand the bound flows. Task 4 replaces the engine's
   * own with `providers.withClient(client, bus)` so registered facets bind too.
   */
  buildProviders: (bus: Events.IBus) => Providers<Profile>
  buildFlows: (deps: {
    sessions: SessionsImpl
    identities: IdentitiesImpl<Profile>
    providers: Providers<Profile>
    events: Events.IBus
    stores: Bound.Stores<Profile, OrgMeta>
  }) => FlowsImpl<Profile>
}): Bound.AuthEngine<Profile, OrgMeta> {
  const { client } = args
  const stores: Bound.Stores<Profile, OrgMeta> = {
    identities: rebindStore(args.stores.identities, client, 'identities'),
    sessions: rebindStore(args.stores.sessions, client, 'sessions'),
    credentials: rebindStore(args.stores.credentials, client, 'credentials'),
    ...(args.stores.orgs && { orgs: rebindStore(args.stores.orgs, client, 'orgs') }),
  }

  const { bus, pending } = createPending(args.events)

  const identities = new IdentitiesImpl<Profile>(stores.identities, bus, args.identitiesCfg)
  const sessions = new SessionsImpl(stores.sessions, bus, args.sessionsCfg)
  const orgs = stores.orgs ? new OrgsImpl<OrgMeta>(stores.orgs, bus) : null
  const providers = args.buildProviders(bus)
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
