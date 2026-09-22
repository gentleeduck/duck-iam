import { AuthError } from '../errors'
import type { Events } from '../events/events.types'
import type { Identities } from '../identities'
import {
  canonicalProviderId,
  describeProviderId,
  echoableProviderId,
  isSignInCapability,
  isUnreachableCapability,
} from './provider.constants'
import type { Provider } from './provider.types'

/**
 * Holds every configured capability, sign-in providers and attach-only facets like mfa and api-key alike,
 * routing `begin`/`complete` by id and resolving facets by type through `resolve`.
 */
export class Providers<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase> {
  private readonly _byId = new Map<string, Provider.Capability>()

  constructor(capabilities: Provider.Capability[] = []) {
    this.registerAll(capabilities)
  }

  /** The runtime hook, so a plugin can add a capability after construction. */
  register(cap: Provider.Capability): void {
    this.registerAll([cap])
  }

  /**
   * Registers a whole list, or none of it. There is no way to take a capability back out, so a list
   * that raises on its third entry would otherwise leave the first two behind for the engine's life.
   */
  registerAll(capabilities: Provider.Capability[]): void {
    const staged = new Map<string, Provider.Capability>()
    for (const cap of capabilities) staged.set(this._assertRegistrable(cap, staged), cap)
    for (const [id, cap] of staged) this._byId.set(id, cap)
  }

  /** Re-binds every capability that knows how and keeps the rest as they are. Registration order and every
   *  id survive, so `resolve()` and `list()` behave identically on the copy. */
  withClient(stores: Provider.Stores, events: Events.IBus): Providers<Profile> {
    const rebound: Provider.Capability[] = []
    for (const cap of this._byId.values()) {
      rebound.push(cap.withClient?.(stores, events) ?? cap)
    }
    // `register` throws on a duplicate id, so a withClient answering a capability under a different id
    // fails loudly rather than shadowing one.
    return new Providers<Profile>(rebound)
  }

  /** The registered capability that is an instance of `ctor`, or null. */
  resolve<T>(ctor: new (...args: never[]) => T): T | null {
    let found: { cap: T; id: string } | null = null
    for (const [id, cap] of this._byId) {
      if (!(cap instanceof ctor)) continue
      if (found) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: `capabilities "${found.id}" and "${id}" both answer ${ctor.name}; register one of them`,
        })
      }
      found = { cap, id }
    }
    return found ? found.cap : null
  }

  /** Sign-in grid: only capabilities that can actually complete a sign-in. */
  list(): { id: string; kind: string }[] {
    return [...this._byId.values()].filter(isSignInCapability).map((c) => ({ id: c.id, kind: c.kind }))
  }

  /** Whether a provider is registered under this id, canonicalised. */
  has(id: string): boolean {
    const canonical = canonicalProviderId(id)
    return canonical !== null && this._byId.has(canonical)
  }

  /** The capability registered under this id; throws when there is none. */
  get(id: string): Provider.Capability {
    const canonical = canonicalProviderId(id)
    const cap = canonical === null ? undefined : this._byId.get(canonical)
    if (!cap) {
      // The id came from a request, so only one that could have been registered is quoted back.
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: echoableProviderId(id),
        detail: 'unknown provider id',
      })
    }
    return cap
  }

  /** Narrow a registered capability to a sign-in provider, or throw. */
  private _signIn(id: string): Provider.Me<unknown, unknown, Profile> {
    const cap = this.get(id)
    // The type guard narrows without a cast and answers the original instance, so `this` stays bound
    // when a facet-style provider's begin/complete run.
    if (!isSignInCapability<Profile>(cap)) {
      // Its own code: "there is no such provider" and "that one signs nobody in" are different
      // things to have done wrong, and `detail` is not a contract a caller can branch on.
      throw new AuthError('AUTH_PROVIDER_UNSUPPORTED', {
        providerId: cap.id,
        detail: 'provider does not sign anyone in',
      })
    }
    return cap
  }

  private _assertRegistrable(cap: Provider.Capability, staged: ReadonlyMap<string, Provider.Capability>): string {
    const id = canonicalProviderId(cap?.id)
    if (id === null) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `provider id ${describeProviderId(cap?.id)} is not a usable id`,
      })
    }
    if (this._byId.has(id) || staged.has(id)) {
      throw new AuthError('AUTH_MISCONFIGURED', { detail: `provider id "${id}" registered twice` })
    }
    if ((typeof cap.begin === 'function') !== (typeof cap.complete === 'function')) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `provider "${id}" implements one of begin/complete; signing in needs both`,
      })
    }
    if (isUnreachableCapability(cap)) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `capability "${id}" has no begin/complete and no prototype, so nothing can reach it`,
      })
    }
    return id
  }

  /** Runs the begin step of the sign-in provider registered under this id. */
  async begin(id: string, ctx: Provider.Context<Profile>, input: unknown): Promise<Provider.Intent[]> {
    return this._signIn(id).begin(ctx, input)
  }

  /** Runs the complete step of the sign-in provider registered under this id. */
  async complete(id: string, ctx: Provider.Context<Profile>, input: unknown): Promise<Provider.InternalIntent[]> {
    return this._signIn(id).complete(ctx, input)
  }
}
