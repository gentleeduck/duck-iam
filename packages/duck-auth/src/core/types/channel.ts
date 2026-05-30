import type { TenantContext } from './context'
import type { Identity } from './identity'

/** Outbound message channel (email / SMS / web-push). Library pre-signs URLs; templates get safe vars only. */
export namespace Channel {
  export type Kind = 'email' | 'sms' | 'webpush'

  export interface SendInput<Vars = Record<string, unknown>> {
    /** Resolved recipient - the channel decides which `identity.profile` field to use. */
    identity: Identity.IIdentity<unknown>
    /** Library-chosen template id; channel impl maps to its own template store. */
    templateId: string
    /** Pre-rendered vars (URLs already signed, strings already i18n-resolved). */
    vars: Vars
    tenant: TenantContext
  }

  export interface SendResult {
    ok: boolean
    /** Provider-side id (for support diagnostics). Channels may omit. */
    providerMessageId?: string
    error?: string
  }

  export interface IChannel<Vars = Record<string, unknown>> {
    readonly kind: Kind
    readonly id: string
    send(input: SendInput<Vars>): Promise<SendResult>
  }
}
