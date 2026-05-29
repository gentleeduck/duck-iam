import type { AuthRoot } from './auth'
import type { Events } from './types/events'
import type { Provider } from './types/provider'

/**
 * Plugin registry. Generic over the AuthRoot generics so `install` does not
 * need a cast at the call site; `AuthRoot.use(plugin)` forwards its own
 * generics unchanged.
 */
export class PluginRegistry<Profile = unknown, Tenant = string, OrgMeta = unknown> {
  private readonly _plugins = new Map<string, PluginRegistry.IAuthPlugin<Profile, Tenant, OrgMeta>>()
  private readonly _eventUnsubs: Array<() => void> = []

  /** All installed plugins keyed by id. */
  get installed(): ReadonlyMap<string, PluginRegistry.IAuthPlugin<Profile, Tenant, OrgMeta>> {
    return this._plugins
  }

  /** Mounted facets keyed by plugin id; consumer-side narrowing required. */
  readonly facets: Record<string, unknown> = {}

  /**
   * Install a plugin atomically.
   */
  async install(
    auth: AuthRoot<Profile, Tenant, OrgMeta>,
    plugin: PluginRegistry.IAuthPlugin<Profile, Tenant, OrgMeta>,
  ): Promise<void> {
    if (typeof plugin?.id !== 'string' || plugin.id.length === 0 || plugin.id.length > 128) {
      throw new Error('@gentleduck/auth: plugin.id must be a non-empty string <=128 chars')
    }
    if (this._plugins.has(plugin.id)) {
      throw new Error(`@gentleduck/auth: plugin "${plugin.id}" already installed`)
    }
    this._plugins.set(plugin.id, plugin)

    if (plugin.providers) {
      for (const p of plugin.providers) auth.providers.register(p)
    }

    if (plugin.events) {
      for (const [event, handler] of Object.entries(plugin.events)) {
        if (handler === undefined) continue
        const unsub = auth.events.on(event as keyof Events.EventMap, handler as (p: unknown) => void | Promise<void>)
        this._eventUnsubs.push(unsub)
      }
    }

    if (plugin.facet !== undefined) {
      this.facets[plugin.id] = plugin.facet
    }

    if (plugin.install) {
      await plugin.install(auth)
    }
  }

  /**
   * Tear down every event subscription wired by installed plugins.
   */
  dispose(): void {
    for (const unsub of this._eventUnsubs) unsub()
    this._eventUnsubs.length = 0
  }
}

/**
 * Namespace merge for `PluginRegistry`. Co-locates the flat type exports
 * alongside the primary symbol via TS class+namespace merging.
 */
export namespace PluginRegistry {
  export interface IAuthPlugin<Profile = unknown, Tenant = string, OrgMeta = unknown> {
    /** Stable id; library refuses duplicate ids. */
    id: string
    /** Optional providers to register at install time. */
    providers?: Provider.IProvider<unknown, unknown, Profile>[]
    /** Optional event subscriptions; library auto-attaches on install. */
    events?: Partial<{ [K in keyof Events.EventMap]: (p: Events.EventMap[K]) => void | Promise<void> }>
    /**
     * Optional install hook. Runs once at `auth.use()` time. Receives the
     * AuthRoot so the plugin can read config or wire additional facets.
     */
    install?(auth: AuthRoot<Profile, Tenant, OrgMeta>): void | Promise<void>
    /**
     * Optional custom facet exposed under `auth.plugins.facets[id]`. Authors
     * keep this surface narrow + typed via their own export.
     */
    facet?: unknown
  }
}
