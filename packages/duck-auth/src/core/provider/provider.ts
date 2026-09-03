import { AuthError } from '../errors'
import type { Events } from '../events/events.types'
import type { Identities } from '../identities'
import type { Provider } from './provider.types'

/** Type guard: a capability that exposes begin/complete is a sign-in provider. */
function isSignInCapability<Profile extends Identities.ProfileMetadataBase>(
  cap: Provider.Capability,
): cap is Provider.Me<unknown, unknown, Profile> {
  return typeof cap.begin === 'function' && typeof cap.complete === 'function'
}

/**
 * Provider/capability registry + sign-in dispatch. Holds every configured
 * capability (sign-in providers AND attach-only facets like mfa/api-key),
 * routes `begin/complete` by id, and resolves facets by type via `resolve`.
 */
export class Providers<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase> {
  private readonly _byId = new Map<string, Provider.Capability>()

  constructor(capabilities: Provider.Capability[] = []) {
    for (const c of capabilities) this.register(c)
  }

  /** Allow plugins to register a capability at runtime. */
  register(cap: Provider.Capability): void {
    if (this._byId.has(cap.id)) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `provider id "${cap.id}" registered twice`,
      })
    }
    this._byId.set(cap.id, cap)
  }

  /**
   * Copy this registry, re-binding every capability that knows how and keeping
   * the rest as they are. Preserves registration order and every id, so
   * `resolve()` and `list()` behave identically on the copy.
   */
  withClient(client: unknown, events: Events.IBus): Providers<Profile> {
    const rebound: Provider.Capability[] = []
    for (const cap of this._byId.values()) {
      rebound.push(cap.withClient?.(client, events) ?? cap)
    }
    // `register` throws on a duplicate id, so a withClient that returned a
    // capability under a different id fails loudly instead of shadowing one.
    return new Providers<Profile>(rebound)
  }

  /** The registered capability that is an instance of `ctor`, or null. */
  resolve<T>(ctor: new (...args: never[]) => T): T | null {
    for (const cap of this._byId.values()) {
      if (cap instanceof ctor) return cap
    }
    return null
  }

  /** Sign-in grid: only capabilities that can actually complete a sign-in. */
  list(): { id: string; kind: string }[] {
    return [...this._byId.values()]
      .filter((c) => typeof c.complete === 'function')
      .map((c) => ({ id: c.id, kind: c.kind }))
  }

  has(id: string): boolean {
    return this._byId.has(id)
  }

  get(id: string): Provider.Capability {
    const p = this._byId.get(id)
    if (!p) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: id,
        detail: 'unknown provider id',
      })
    }
    return p
  }

  /** Narrow a registered capability to a sign-in provider, or throw. */
  private _signIn(id: string): Provider.Me<unknown, unknown, Profile> {
    const cap = this.get(id)
    // Type-guard narrows without a cast AND returns the original instance, so
    // `this` stays bound when begin/complete run (facet-style providers).
    if (!isSignInCapability<Profile>(cap)) {
      throw new AuthError('AUTH_PROVIDER_FAILED', { providerId: id, detail: 'not a sign-in provider' })
    }
    return cap
  }

  async begin(id: string, ctx: Provider.Context<Profile>, input: unknown): Promise<Provider.Intent[]> {
    return this._signIn(id).begin(ctx, input)
  }

  async complete(id: string, ctx: Provider.Context<Profile>, input: unknown): Promise<Provider.InternalIntent[]> {
    return this._signIn(id).complete(ctx, input)
  }
}
