/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { TenantContext } from './context'
import type { Identity } from './identity'

/**
 * Outbound message channel - email, SMS, web-push. Library ships the contract;
 * adapters (resend / postmark / sendgrid / smtp / twilio / vonage / webpush)
 * ship in `src/channels/<kind>/<provider>`.
 *
 * Channels never accept plaintext secrets - magic-link URLs are pre-signed by
 * the library before reaching the channel; templates only receive safe vars.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
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
