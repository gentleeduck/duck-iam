/** Vue client types — the public `VueClient` namespace. */
import type { Identity } from '~/core/identities'
import type { Envelope } from '~/core/types/session'
import type { VanillaClient } from '../vanilla'

export namespace VueClient {
  /** Minimal `Ref<T>` surface compatible with Vue 3 `vue.ref`. */
  export type Ref<T> = {
    value: T
  }

  export type VueModule = {
    ref<T>(value: T): VueClient.Ref<T>
    inject(key: symbol): unknown
    provide(key: symbol, value: any): void
  }

  export type App = {
    provide(key: symbol, value: unknown): VueClient.App
  }

  export type Plugin = {
    install(app: VueClient.App): void
  }

  export interface IConfig<Profile extends Identity.ProfileMetadataBase> extends VanillaClient.Config {
    /** Pre-built client; overrides config. */
    client?: VanillaClient.Client<Profile>
    /** Disable the initial automatic /session fetch on plugin install. */
    noInitialFetch?: boolean
  }

  export type Injected<Profile extends Identity.ProfileMetadataBase> = {
    client: VanillaClient.Client<Profile>
    state: VueClient.Ref<VanillaClient.SessionResult<Profile>>
    status: VueClient.Ref<'loading' | 'authed' | 'guest'>
    refresh(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
  }

  export type UseSessionResult<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase> = {
    data: VueClient.Ref<VanillaClient.SessionResult<Profile>>
    status: VueClient.Ref<'loading' | 'authed' | 'guest'>
    refresh(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
  }

  export type MutationResult<I, O> = {
    mutate(input: I): Promise<O>
    loading: VueClient.Ref<boolean>
    error: VueClient.Ref<unknown | null>
  }
}
