/**
 * SMTP channel adapter. Wraps a nodemailer-compatible transporter so
 * consumers can plug in any SMTP relay (their own MTA, AWS SES,
 * Mailgun, Postmark via SMTP, Resend SMTP, etc.) without committing
 * the auth lib to a specific provider SDK.
 */

import { getProfileString } from '../../core/credential-utils'
import { AuthErrorObject } from '../../core/errors'
import type { Channel } from '../../core/types/channel'

/**
 * Public surface for the SMTP channel. Every type lives inside the
 * namespace so consumers reach for `SmtpChannel.IConfig` /
 * `SmtpChannel.ITransporter` instead of a flat name.
 */
export namespace SmtpChannel {
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

  /** Config knobs for {@link SmtpChannel}. */
  export interface IConfig {
    /** Transporter implementing `sendMail`. Required. */
    transporter: ITransporter
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
export class SmtpChannel implements Channel.IChannel {
  readonly kind: Channel.Kind = 'email'
  readonly id: string
  private readonly _transporter: SmtpChannel.ITransporter
  private readonly _from: string
  private readonly _resolve: SmtpChannel.ITemplateResolver

  constructor(cfg: SmtpChannel.IConfig) {
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
   * email to the configured SMTP transporter. Returns ok:false with
   * the underlying error message on transporter failure so the caller
   * can retry / escalate without exception escape.
   */
  async send(input: Channel.SendInput): Promise<Channel.SendResult> {
    // cast-free email extraction - rejects non-string `email`
    // (would otherwise have propagated into the SMTP `To:` header
    // via the cast, with unpredictable downstream behavior).
    const to = getProfileString(input.identity.profile, 'email')
    if (!to) {
      return { ok: false, error: 'identity has no email; SmtpChannel cannot deliver' }
    }
    let resolved: Awaited<ReturnType<SmtpChannel.ITemplateResolver>>
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
