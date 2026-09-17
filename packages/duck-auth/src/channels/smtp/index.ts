/**
 * SMTP channel adapter. Wraps a nodemailer-compatible transporter so
 * consumers can plug in any SMTP relay (their own MTA, AWS SES,
 * Mailgun, Postmark via SMTP, Resend SMTP, etc.) without committing
 * the auth lib to a specific provider SDK.
 */

import type { Channel } from '~/channels/channels.types'
import { AuthError } from '~/core/errors'
import { ChannelGuard } from '../channels.guard'
import { checkRenderedEmail, describeSendError, resolveEmailRecipient, sanitizeSubject } from '../channels.outbound'

export namespace AuthSmtpChannel {
  /**
   * Subset of the nodemailer transporter API we depend on. Any
   * nodemailer-compatible transport (the real createTransport return
   * value, AWS SES `nodemailer` transport, a test double) satisfies
   * this shape - no hard dependency on nodemailer types.
   */
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

  /**
   * Template resolver. Given the auth lib's `templateId` + the
   * rendered `vars`, return the email body content. Apps own all
   * template content; the auth lib only provides the (templateId,
   * vars) pair.
   */
  export type ITemplateResolver = (
    templateId: string,
    vars: Record<string, unknown>,
  ) => Promise<{ subject: string; text?: string; html?: string }> | { subject: string; text?: string; html?: string }

  /** Cfg knobs for {@link AuthSmtpChannel}. */
  export interface Cfg<TTransporter extends ITransporter = ITransporter> extends ChannelGuard.Cfg {
    /** Transporter implementing `sendMail`. Required. */
    transporter: TTransporter
    /** From: address. Required (SMTP refuses bare envelopes). */
    from: string
    /** Template resolver invoked per send. Required. */
    templates: ITemplateResolver
    /** Identifier appearing in logs + diagnostics. Default 'smtp'. */
    id?: string
  }
}

/**
 * SMTP channel implementation of `Channel.IChannel`. Reads the
 * recipient email from `input.identity.profile.email`; rejects with
 * AUTH/MISCONFIGURED when the identity has no email.
 */
export class AuthSmtpChannel<TTransporter extends AuthSmtpChannel.ITransporter = AuthSmtpChannel.ITransporter>
  implements Channel.Channel
{
  readonly kind: Channel.Kind = 'email'
  readonly id: string
  private readonly _transporter: TTransporter
  private readonly _from: string
  private readonly _resolve: AuthSmtpChannel.ITemplateResolver
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

  /**
   * Resolve the template, look up the recipient, hand the rendered
   * email to the configured SMTP transporter. Returns ok:false with
   * the underlying error message on transporter failure so the caller
   * can retry / escalate without exception escape.
   */
  async send(input: Channel.SendInput): Promise<Channel.SendResult> {
    const recipient = resolveEmailRecipient(input.identity.profile, 'AuthSmtpChannel')
    if (!recipient.ok) return { error: recipient.error, ok: false, retryable: false }
    const denied = await this._guard.spend(input)
    if (denied) return { error: denied, ok: false, retryable: true }
    const to = recipient.to
    let resolved: Awaited<ReturnType<AuthSmtpChannel.ITemplateResolver>>
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

/** Factory around {@link AuthSmtpChannel}, for callers who prefer functions to `new`. */
export function authSmtpChannel(...args: ConstructorParameters<typeof AuthSmtpChannel>): AuthSmtpChannel {
  return new AuthSmtpChannel(...args)
}
