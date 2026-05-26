/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { AuthRoot } from './auth'
import type { Events } from './types/events'
import type { Provider } from './types/provider'

/**
 * Plugin contract. Authors ship a plugin that may register providers,
 * subscribe events, and add custom facets onto `auth.plugins.<id>.*`.
 *
 * DESIGN section 10. Plugins are first-class - installed via `auth.use(plugin)`
 * which wires their providers + events into the AuthRoot atomically.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface AuthPlugin<Profile = unknown, Tenant = string, OrgMeta = unknown> {
  /** Stable id; library refuses duplicate ids. */
  id: string
  /** Optional providers to register at install time. */
  providers?: Provider.IProvider<unknown, unknown, Profile>[]
  /** Optional event subscriptions; library auto-attaches on install. */
  events?: Partial<{ [K in keyof Events.EventMap]: (p: Events.EventMap[K]) => void | Promise<void> }>
  /**
   * Optional install hook. Runs once at `auth.use()` time. Receives the
   * AuthRoot so the plugin can read config or wire additional facets.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  install?(auth: AuthRoot<Profile, Tenant, OrgMeta>): void | Promise<void>
  /**
   * Optional custom facet exposed under `auth.plugins.<id>`. Authors are
   * expected to keep this surface narrow + typed via their own export.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  facet?: unknown
}

/**
 * Plugin registry. Composed into `AuthRoot.plugins.<id>` so the call site
 * `auth.plugins.stripe.charge(...)` reads naturally. The registry is
 * generic over the plugin map for end-to-end typing.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class PluginRegistry {
  private readonly _plugins = new Map<string, AuthPlugin>()
  private readonly _eventUnsubs: Array<() => void> = []

  /** All installed plugins keyed by id. */
  get installed(): ReadonlyMap<string, AuthPlugin> {
    return this._plugins
  }

  /** Mounted facets keyed by plugin id; consumer-side narrowing required. */
  readonly facets: Record<string, unknown> = {}

  async install(auth: AuthRoot, plugin: AuthPlugin): Promise<void> {
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

  /** Tear down every event subscription wired by installed plugins. */
  dispose(): void {
    for (const unsub of this._eventUnsubs) unsub()
    this._eventUnsubs.length = 0
  }
}
