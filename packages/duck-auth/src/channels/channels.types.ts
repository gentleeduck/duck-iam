import type { TenantContext } from '~/core'
import type { Identities } from '~/core/identities'

/** Outbound message channel (email / SMS / web-push). Library pre-signs URLs; templates get safe vars only. */
export namespace Channel {
  export type Kind = 'email' | 'sms' | 'webpush'

  /** Renders a template id and its vars into the subject and body an email channel sends. SMS and web-push
   *  answer different shapes, so each declares its own. */
  export type IEmailTemplateResolver = (
    templateId: string,
    vars: Record<string, unknown>,
  ) => Promise<{ subject: string; text?: string; html?: string }> | { subject: string; text?: string; html?: string }

  export type SendInput<
    Vars = Record<string, unknown>,
    Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  > = {
    /** The resolved recipient; the channel decides which `identity.profile` field to address. */
    identity: Identities.Me<Profile>
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
    /**
     * Whether sending the same message again could succeed. A refused recipient and a template that
     * threw are wiring faults, and reporting them in the same shape as a network outage makes retry
     * logic keyed on this result retry something that will never work.
     */
    retryable?: boolean
  }

  export type Channel<Vars = Record<string, unknown>> = {
    readonly kind: Kind
    readonly id: string
    send(input: SendInput<Vars>): Promise<SendResult>
  }
}
