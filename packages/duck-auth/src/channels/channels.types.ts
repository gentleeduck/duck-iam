import type { TenantContext } from '~/core'
import type { Identity } from '~/core/identities'

/** Outbound message channel (email / SMS / web-push). Library pre-signs URLs; templates get safe vars only. */
export namespace Channel {
  export type Kind = 'email' | 'sms' | 'webpush'

  export type SendInput<
    Vars = Record<string, unknown>,
    Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
  > = {
    /** Resolved recipient - the channel decides which `identity.profile` field to use. */
    identity: Identity.Me<Profile>
    /** Library-chosen template id; channel impl maps to its own template store. */
    templateId: string
    /** Pre-rendered vars (URLs already signed, strings already i18n-resolved). */
    vars: Vars
    tenant: TenantContext
  }

  export type SendResult = {
    ok: boolean
    /** Provider-side id (for support diagnostics). Channels may omit. */
    providerMessageId?: string
    error?: string
  }

  export type Channel<Vars = Record<string, unknown>> = {
    readonly kind: Kind
    readonly id: string
    send(input: SendInput<Vars>): Promise<SendResult>
  }
}
