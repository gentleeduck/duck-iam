import type { Channel } from '~/channels/channels.types'

/** Magic-link options: the channel it sends over, and the token's lifetime. */
export namespace MagicLink {
  export interface Options<Profile = unknown> {
    /** Keyed by their `kind`. */
    channels: { email?: Channel.Channel; sms?: Channel.Channel; webpush?: Channel.Channel }
    /** How the library finds an identity from an email. Returning `null` and rejecting with an absence
     *  code both read as "no such address", so `auth.identities.getByEmail` wires straight in. */
    findIdentityByEmail: (email: string, tenantId?: string) => Promise<{ id: string } | null>
    /** Creates an identity when no one matches the email. Default false. */
    autoCreateIdentity?: boolean
    /** The `profile` payload used when auto-creating. */
    autoCreateProfile?: (email: string) => Profile
    /** Default 10 minutes. */
    ttlMs?: number
    /** Default 'magic-link:request:'. */
    limiterKeyPrefix?: string
    /** Where the link lands; the token is appended as `?token=`. */
    callbackPath?: string
  }

  export interface BeginInput {
    email: string
    /** Which channel sends the link; it must be one the engine was configured with. */
    channel?: 'email' | 'sms' | 'webpush'
  }

  export interface CompleteInput {
    token: string
  }

  /** Shape stored in `Credential.metadata` for magic-link credentials. */
  export interface CredentialMetadata {
    email: string
    /** The channel the link went out over, recorded on the row. */
    channel: 'email' | 'sms' | 'webpush'
  }
}
