import type { TenantContext } from '~/core'
import type { Events } from '~/core/events'
import type { Identities } from '~/core/identities'

/** Every outbound token the library mints. The host's {@link Deliver} switches on it. */
export type DeliveryKind =
  | 'account-deletion'
  | 'account-deletion-cancel'
  | 'email-verification'
  | 'magic-link'
  | 'password-reset'

/** What the host is handed for one outbound message: the recipient's whole identity, the vars with the
 *  URL already signed, and the tenant. Throw to report a failure; the thrown value is never read. */
export type Deliver = (message: {
  kind: DeliveryKind
  identity: Identities.Me
  vars: Record<string, unknown>
  tenant: TenantContext
}) => Promise<void>

/** Calls the host's `deliver` and turns a refusal into an event rather than an exception. */
export async function deliver(
  events: Pick<Events.IBus, 'emit'>,
  kind: DeliveryKind,
  send: Deliver,
  message: { identity: Identities.Me; vars: Record<string, unknown>; tenant: TenantContext },
): Promise<void> {
  try {
    await send({ kind, ...message })
  } catch {
    // Not the thrown error's text: it carries whatever the host's mailer put in the message, which is the
    // recipient and the rendered body with the token URL in it. Fixed text, audited, never the error's.
    await events.emit('signin.failed', { providerId: kind, reason: 'deliver threw' })
  }
}
