import { AuthError } from '../errors'
import type { Identity } from '../types'
import type { Provider } from './provider.types'

/**
 * Providers facet - registry + dispatch. Holds the configured {@link Provider.IProvider}
 * list and routes `begin / complete` calls by id. Provider implementations are pure;
 * the framework adapter executes the Intent[] they return against the actual HTTP layer.
 */
export class ProvidersFacet<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase> {
  private readonly _byId = new Map<string, Provider.Me<unknown, unknown, Profile>>()

  constructor(providers: Provider.Me<unknown, unknown, Profile>[] = []) {
    for (const p of providers) this._add(p)
  }

  private _add(p: Provider.Me<unknown, unknown, Profile>): void {
    if (this._byId.has(p.id)) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `provider id "${p.id}" registered twice`,
      })
    }
    this._byId.set(p.id, p)
  }

  /** List registered provider ids. UI uses this to render the signin grid. */
  list(): { id: string; kind: Provider.Me['kind'] }[] {
    return [...this._byId.values()].map((p) => ({ id: p.id, kind: p.kind }))
  }

  has(id: string): boolean {
    return this._byId.has(id)
  }

  get(id: string): Provider.Me<unknown, unknown, Profile> {
    const p = this._byId.get(id)
    if (!p) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: id,
        detail: 'unknown provider id',
      })
    }
    return p
  }

  /** Allow plugins to register a provider at runtime. */
  register(p: Provider.Me<unknown, unknown, Profile>): void {
    this._add(p)
  }

  async begin(id: string, ctx: Provider.Context<Profile>, input: unknown): Promise<Provider.Intent[]> {
    return this.get(id).begin(ctx, input)
  }

  async complete(id: string, ctx: Provider.Context<Profile>, input: unknown): Promise<Provider.InternalIntent[]> {
    return this.get(id).complete(ctx, input)
  }
}

export namespace ProvidersFacet {
  // No flat type aliases for this facet (class-only public surface).
}
