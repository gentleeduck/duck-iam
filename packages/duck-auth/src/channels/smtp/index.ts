/** SMTP channel adapter over a nodemailer-compatible transporter, so any relay plugs in without the library
 *  committing to one provider's SDK. */

import type { Channel } from '~/channels/channels.types'
import { AuthError } from '~/core/errors'
import { ChannelGuard } from '../channels.guard'
import { checkRenderedEmail, describeSendError, resolveEmailRecipient, sanitizeSubject } from '../channels.outbound'

export namespace AuthSmtpChannel {
  /** The subset of the nodemailer transporter API this uses, so a real transport or a test double satisfies
   *  it without a hard dependency on nodemailer's types. */
  export interface ITransporter {
    sendMail(opts: {
      from: string
      to: string
      subject: string
      text?: string
      html?: string
      headers?: Record<string, string>
    }): Promise<{ messageId?: string }>
  }

  /** Turn a `templateId` and its `vars` into the email body. Apps own every template; the library supplies only
   *  that pair. */
  export interface Cfg<TTransporter extends ITransporter = ITransporter> extends ChannelGuard.Cfg {
    /** Transporter implementing `sendMail`. Required. */
    transporter: TTransporter
    /** From: address. Required (SMTP refuses bare envelopes). */
    from: string
    /** Template resolver invoked per send. Required. */
    templates: Channel.IEmailTemplateResolver
    /** Identifier appearing in logs + diagnostics. Default 'smtp'. */
    id?: string
  }
}

/** `Channel.Channel` over SMTP. Takes the recipient from `input.identity.profile.email` and refuses with
 *  AUTH_MISCONFIGURED when the identity has none. */
export class AuthSmtpChannel<TTransporter extends AuthSmtpChannel.ITransporter = AuthSmtpChannel.ITransporter>
  implements Channel.Channel
{
  readonly kind: Channel.Kind = 'email'
  readonly id: string
  private readonly _transporter: TTransporter
  private readonly _from: string
  private readonly _resolve: Channel.IEmailTemplateResolver
  private readonly _guard: ChannelGuard

  constructor(cfg: AuthSmtpChannel.Cfg<TTransporter>) {
    if (!cfg.from) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthSmtpChannel requires a non-empty `from` address',
      })
    }
    this._transporter = cfg.transporter
    this._from = cfg.from
    this._resolve = cfg.templates
    this.id = cfg.id ?? 'smtp'
    this._guard = new ChannelGuard(this.id, cfg)
  }

  /** Resolve the template, find the recipient, hand the rendered mail to the transporter. A transporter failure
   *  comes back as `ok: false` with its message, so a caller can retry or escalate without catching. */
  async send(input: Channel.SendInput): Promise<Channel.SendResult> {
    const recipient = resolveEmailRecipient(input.identity.profile, 'AuthSmtpChannel')
    if (!recipient.ok) return { error: recipient.error, ok: false, retryable: false }
    const budget = await this._guard.spend(input).wrap()
    if (budget.error) return { error: budget.error.code, ok: false, retryable: true }
    const to = recipient.to
    let resolved: Awaited<ReturnType<Channel.IEmailTemplateResolver>>
    try {
      resolved = await this._resolve(input.templateId, input.vars)
    } catch (err) {
      return { error: describeSendError(err), ok: false, retryable: false }
    }
    const malformed = checkRenderedEmail(resolved)
    if (malformed) return { error: `AuthSmtpChannel: ${malformed}`, ok: false, retryable: false }
    try {
      const result = await this._guard.attempt(() =>
        this._transporter.sendMail({
          from: this._from,
          to,
          subject: sanitizeSubject(resolved.subject),
          ...(resolved.text !== undefined && { text: resolved.text }),
          ...(resolved.html !== undefined && { html: resolved.html }),
        }),
      )
      const out: Channel.SendResult = { ok: true }
      if (result.messageId !== undefined) out.providerMessageId = result.messageId
      return out
    } catch (err) {
      return { error: describeSendError(err), ok: false, retryable: true }
    }
  }
}

/** Email channel over SMTP. */
export function authSmtpChannel(...args: ConstructorParameters<typeof AuthSmtpChannel>): AuthSmtpChannel {
  return new AuthSmtpChannel(...args)
}
