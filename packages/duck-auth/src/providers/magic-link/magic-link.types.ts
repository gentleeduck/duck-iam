import type { Channel } from '~/channels/channels.types'

/**
 * Every type the magic-link provider exposes lives under this one namespace, so
 * consumers reach for `MagicLink.Options`, `MagicLink.BeginInput`, etc. from a
 * single place.
 */
export namespace MagicLink {
  /** Cfg knobs for {@link magicLink}. */
  export interface Options<Profile = unknown> {
    /** Channel implementations keyed by their `kind`. */
    channels: { email?: Channel.Channel; sms?: Channel.Channel; webpush?: Channel.Channel }
    /** Library uses this to find the identity given an email. */
    findIdentityByEmail: (email: string, tenantId?: string) => Promise<{ id: string } | null>
    /**
     * Optional auto-create - if no identity matches the email, create
     * one on link request. Default false.
     */
    autoCreateIdentity?: boolean
    /** Used as the `profile` payload when autoCreating. */
    autoCreateProfile?: (email: string) => Profile
    /** TTL of magic-link token in ms. Default 10 minutes. */
    ttlMs?: number
    /** Per-email rate limit prefix. Default 'magic-link:request:'. */
    limiterKeyPrefix?: string
    /** Path the link lands on; sid appended as `?token=`. */
    callbackPath?: string
  }

  /** Input to begin. */
  export interface BeginInput {
    email: string
    channel?: 'email' | 'sms' | 'webpush'
  }

  /** Input to complete. */
  export interface CompleteInput {
    token: string
  }

  /** Shape stored in `Credential.metadata` for magic-link credentials. */
  export interface CredentialMetadata {
    email: string
    channel: 'email' | 'sms' | 'webpush'
  }
}
