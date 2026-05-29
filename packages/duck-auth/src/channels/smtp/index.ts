/**
 * @packageDocumentation
 * SMTP channel adapter. Wraps a nodemailer-compatible transporter so
 * consumers can plug in any SMTP relay (their own MTA, AWS SES,
 * Mailgun, Postmark via SMTP, Resend SMTP, etc.) without committing
 * the auth lib to a specific provider SDK.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../../core/errors'
import type { Channel } from '../../core/types/channel'

/**
 * Subset of the nodemailer transporter API we depend on. Keeping it
 * narrow lets consumers pass any nodemailer-compatible transport (the
 * real `nodemailer.createTransport` return value, AWS SES `nodemailer`
 * transport, a test double, etc.) without taking nodemailer as a hard
 * dependency.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface SmtpTransporterLike {
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
 * Template resolver. Given the auth lib's `templateId` + the rendered
 * `vars`, return the email body content the SMTP transporter will send.
 * Apps own all template content; the auth lib only provides the
 * (templateId, vars) pair that lands in this hook.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export type SmtpTemplateResolver = (
  templateId: string,
  vars: Record<string, unknown>,
) => Promise<{ subject: string; text?: string; html?: string }> | { subject: string; text?: string; html?: string }

/**
 * Config knobs for `SmtpChannel`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface SmtpChannelConfig {
  /** Transporter implementing `sendMail`. Required. */
  transporter: SmtpTransporterLike
  /** From: address. Required (SMTP refuses bare envelopes). */
  from: string
  /** Template resolver invoked per send. Required. */
  templates: SmtpTemplateResolver
  /** Identifier appearing in logs + diagnostics. Default 'smtp'. */
  id?: string
}

/**
 * SMTP channel implementation of `Channel.IChannel`. Reads the
 * recipient email from `input.identity.profile.email` (the convention
 * the password + magic-link providers expect); rejects with
 * AUTH/MISCONFIGURED when the identity has no email.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class SmtpChannel implements Channel.IChannel {
  readonly kind: Channel.Kind = 'email'
  readonly id: string
  private readonly _transporter: SmtpTransporterLike
  private readonly _from: string
  private readonly _resolve: SmtpTemplateResolver

  constructor(cfg: SmtpChannelConfig) {
    if (!cfg.from) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'SmtpChannel requires a non-empty `from` address',
      })
    }
    this._transporter = cfg.transporter
    this._from = cfg.from
    this._resolve = cfg.templates
    this.id = cfg.id ?? 'smtp'
  }

  /**
   * Resolve the template, look up the recipient, hand the rendered
   * email to the configured SMTP transporter. Returns ok:false with the
   * underlying error message when the transporter rejects so the
   * caller can retry or escalate without the exception escaping the
   * channel boundary.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async send(input: Channel.SendInput): Promise<Channel.SendResult> {
    const profile = input.identity.profile as { email?: string } | undefined
    const to = profile?.email
    if (!to) {
      return { ok: false, error: 'identity has no email; SmtpChannel cannot deliver' }
    }
    let resolved: Awaited<ReturnType<SmtpTemplateResolver>>
    try {
      resolved = await this._resolve(input.templateId, input.vars as Record<string, unknown>)
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
    try {
      const result = await this._transporter.sendMail({
        from: this._from,
        to,
        subject: resolved.subject,
        ...(resolved.text !== undefined && { text: resolved.text }),
        ...(resolved.html !== undefined && { html: resolved.html }),
      })
      const out: Channel.SendResult = { ok: true }
      if (result.messageId !== undefined) out.providerMessageId = result.messageId
      return out
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
  }
}

/**
 * Namespace merge for `SmtpChannel`. Co-locates config + helper types
 * alongside the class.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace SmtpChannel {
  /** Alias for `SmtpChannelConfig`. */
  export type IConfig = SmtpChannelConfig
  /** Alias for `SmtpTransporterLike`. */
  export type ITransporter = SmtpTransporterLike
  /** Alias for `SmtpTemplateResolver`. */
  export type ITemplateResolver = SmtpTemplateResolver
}
