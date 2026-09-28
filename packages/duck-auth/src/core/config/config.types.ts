import type { Deliver } from '~/core/flows/flows.delivery'
import type { Compliance } from '../compliance/compliance.types'
import type { AuthEngine, Engine } from '../engine'
import type { Identities } from '../identities/identities.types'
import type { Provider } from '../provider/provider.types'
import type { Transport } from '../transport/transport.types'

/** The declarative config `createAuth` accepts, before it is resolved into an engine. */
export namespace AuthDefine {
  /**
   * Skipped-or-included provider entry. Falsy values silently dropped.
   * Thunks receive the constructed `AuthEngine` and the host's `deliver`, so magic-link and OTP can bind
   * both without repeating config.
   */
  export type IProviderEntry<
    Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
    Tenant = string,
    OrgMeta = unknown,
  > =
    | Provider.Capability
    | false
    | null
    | undefined
    | ''
    | ((
        auth: AuthEngine<Profile, Tenant, OrgMeta>,
        deliver: Deliver | undefined,
      ) => Provider.Capability | false | null | undefined | '')

  /**
   * Input shape for `createAuth`. Flat, ergonomic alternative to constructing
   * {@link AuthEngine} directly.
   *
   * @template Profile  - Shape of the user profile stored on identities.
   * @template Tenant   - Tenant discriminator type (phantom; drives type-safety only).
   * @template OrgMeta  - Shape of organization metadata.
   */
  export interface Cfg<
    Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
    Tenant = string,
    OrgMeta = unknown,
  > extends Omit<Engine.Cfg<Profile, Tenant, OrgMeta>, 'providers' | 'transport'> {
    /** Default a `duck-sid` cookie. */
    transport?: Transport.ITransport
    /** Provider array — falsy entries silently skipped. */
    providers?: IProviderEntry<Profile, Tenant, OrgMeta>[]
    /** Which environment's checks `auth.strict({ env })` runs at the end of construction. */
    strict?: 'development' | 'production' | 'test' | false
    /** Compliance preset(s) to shorten the session lifetimes to and hold `strict()` to. */
    compliance?: Compliance.Preset | Compliance.Preset[]
  }
}
