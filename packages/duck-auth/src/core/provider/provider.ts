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
 * Provider/capability registry + sign-in dispatch. Holds every configured
 * capability (sign-in providers AND attach-only facets like mfa/api-key),
 * routes `begin/complete` by id, and resolves facets by type via `resolve`.
 */
export class Providers<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase> {
  private readonly _byId = new Map<string, Provider.Capability>()

  constructor(capabilities: Provider.Capability[] = []) {
    this.registerAll(capabilities)
  }

  /** Allow plugins to register a capability at runtime. */
  register(cap: Provider.Capability): void {
    this.registerAll([cap])
  }

  /**
   * Register a whole list, or none of it. There is no way to take a capability back out, so a list
   * that raised on its third entry used to leave the first two behind for the life of the engine.
   */
  registerAll(capabilities: Provider.Capability[]): void {
    const staged = new Map<string, Provider.Capability>()
    for (const cap of capabilities) staged.set(this._assertRegistrable(cap, staged), cap)
    for (const [id, cap] of staged) this._byId.set(id, cap)
  }

  /**
   * Copy this registry, re-binding every capability that knows how and keeping
   * the rest as they are. Preserves registration order and every id, so
   * `resolve()` and `list()` behave identically on the copy.
   */
  withClient(stores: Provider.Stores, events: Events.IBus): Providers<Profile> {
    const rebound: Provider.Capability[] = []
    for (const cap of this._byId.values()) {
      rebound.push(cap.withClient?.(stores, events) ?? cap)
    }
    // `register` throws on a duplicate id, so a withClient that returned a
    // capability under a different id fails loudly instead of shadowing one.
    return new Providers<Profile>(rebound)
  }

  /**
   * The registered capability that is an instance of `ctor`, or null.
   *
   * Two answers is a configuration error rather than a preference: a plugin that subclasses a
   * shipped facet would otherwise decide what `auth.passwords` returns by registering first.
   */
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

  has(id: string): boolean {
    const canonical = canonicalProviderId(id)
    return canonical !== null && this._byId.has(canonical)
  }

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
    // Type-guard narrows without a cast AND returns the original instance, so
    // `this` stays bound when begin/complete run (facet-style providers).
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

  async begin(id: string, ctx: Provider.Context<Profile>, input: unknown): Promise<Provider.Intent[]> {
    return this._signIn(id).begin(ctx, input)
  }

  async complete(id: string, ctx: Provider.Context<Profile>, input: unknown): Promise<Provider.InternalIntent[]> {
    return this._signIn(id).complete(ctx, input)
  }
}
