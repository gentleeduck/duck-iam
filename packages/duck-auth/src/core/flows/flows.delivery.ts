import type { TenantContext } from '~/core'
import type { Events } from '~/core/events'
import type { Identities } from '~/core/identities'

/** What each kind of message carries: `url` is already signed, and `ttlMin` is how long it stays good. */
type DeliveryVars = {
  'account-deletion': { url: string; ttlMin: number }
  /** `restorableUntil` is epoch ms. */
  'account-deletion-cancel': { url: string; ttlMin: number; restorableUntil: number }
  'email-verification': { url: string; ttlMin: number }
  'magic-link': { url: string; ttlMin: number }
  'password-reset': { url: string; ttlMin: number; requiresMfa: boolean }
}

/** Every outbound token the library mints. The host's {@link Deliver} switches on it. */
export type DeliveryKind = keyof DeliveryVars

/** One outbound message, its `vars` narrowed by `kind`: the recipient's whole identity, and the tenant. */
export type DeliveryMessage = {
  [K in DeliveryKind]: { kind: K; identity: Identities.Me; vars: DeliveryVars[K]; tenant: TenantContext }
}[DeliveryKind]

/** What the host is handed for each outbound message. Throw to report a failure; the thrown value is never read. */
export type Deliver = (message: DeliveryMessage) => Promise<void>

/** Calls the host's `deliver` and turns a refusal into an event rather than an exception. Never rejects, so a
 *  flow can leave it unawaited. */
export async function deliver(
  events: Pick<Events.IBus, 'emit'>,
  send: Deliver,
  message: DeliveryMessage,
): Promise<void> {
  try {
    await send(message)
  } catch {
    // Not the thrown error's text: it carries whatever the host's mailer put in the message, which is the
    // recipient and the rendered body with the token URL in it. Fixed text, audited, never the error's.
    try {
      await events.emit('signin.failed', { providerId: message.kind, reason: 'deliver threw' })
    } catch (err) {
      console.error(`[@gentleduck/auth] could not report a failed ${message.kind} delivery:`, err)
    }
  }
}
