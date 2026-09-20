import { AuthError } from '~/core/errors'
import type { Events } from '~/core/events/events.types'
import type { Provider } from '~/core/provider/provider.types'
import type { AuthEngine } from '../engine'
import type { Identities } from '../identities'

/** Generic over the engine's own generics, so `AuthEngine.use` forwards them and `install` needs no cast. */
export class PluginRegistry<Profile extends Identities.ProfileMetadataBase, Tenant = string, OrgMeta = unknown> {
  private readonly _plugins = new Map<string, PluginRegistry.Plugin<Profile, Tenant, OrgMeta>>()
  private readonly _eventUnsubs: Array<() => void> = []

  get installed(): ReadonlyMap<string, PluginRegistry.Plugin<Profile, Tenant, OrgMeta>> {
    return this._plugins
  }

  /** Keyed by plugin id, and `unknown`, so the consumer narrows. */
  readonly facets: Record<string, unknown> = {}

  /** All of the plugin or none of it: a failure part-way unwinds what landed. */
  async install(
    auth: AuthEngine<Profile, Tenant, OrgMeta>,
    plugin: PluginRegistry.Plugin<Profile, Tenant, OrgMeta>,
  ): Promise<void> {
    if (typeof plugin?.id !== 'string' || plugin.id.length === 0 || plugin.id.length > 128) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: '@gentleduck/auth: plugin.id must be a non-empty string <=128 chars',
      })
    }
    if (this._plugins.has(plugin.id)) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `@gentleduck/auth: plugin "${plugin.id}" already installed`,
      })
    }

    const unsubs: Array<() => void> = []
    try {
      if (plugin.events) {
        for (const [event, handler] of Object.entries(plugin.events)) {
          if (handler === undefined) continue
          unsubs.push(auth.events.on(event as keyof Events.EventMap, handler as (p: unknown) => void | Promise<void>))
        }
      }
      if (plugin.facet !== undefined) {
        this.facets[plugin.id] = plugin.facet
      }
      if (plugin.install) {
        await plugin.install(auth)
      }
      // Providers last, because this is the only step that cannot be undone: `Providers` has no
      // unregister. Registered first, a hook that then threw left its sign-in providers reachable
      // through `signIn` for the life of the engine - wired by a plugin that is not installed, whose
      // `install` never ran and whose facet and events were rolled back around them.
      if (plugin.providers) {
        auth.providers.registerAll(plugin.providers)
      }
    } catch (err) {
      for (const unsub of unsubs) unsub()
      delete this.facets[plugin.id]
      throw err
    }

    this._eventUnsubs.push(...unsubs)
    this._plugins.set(plugin.id, plugin)
  }

  /** Tear down every event subscription wired by installed plugins. */
  dispose(): void {
    for (const unsub of this._eventUnsubs) unsub()
    this._eventUnsubs.length = 0
  }
}

export namespace PluginRegistry {
  export interface Plugin<Profile extends Identities.ProfileMetadataBase, Tenant = string, OrgMeta = unknown> {
    /** Stable id; library refuses duplicate ids. */
    id: string
    /** Optional providers to register at install time. */
    providers?: Provider.Me<unknown, unknown, Profile>[]
    /** Optional event subscriptions; library auto-attaches on install. */
    events?: Partial<{ [K in keyof Events.EventMap]: (p: Events.EventMap[K]) => void | Promise<void> }>
    /**
     * Optional install hook. Runs once at `auth.use()` time. Receives the
     * AuthEngine so the plugin can read config or wire additional facets.
     */
    install?(auth: AuthEngine<Profile, Tenant, OrgMeta>): void | Promise<void>
    /**
     * Optional custom facet exposed under `auth.plugins.facets[id]`. Authors
     * keep this surface narrow + typed via their own export.
     */
    facet?: unknown
  }
}
