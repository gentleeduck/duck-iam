/**
 * @packageDocumentation
 * Resend channel adapter. Wraps the Resend HTTP API via the `resend`
 * npm package (lazy peerDep) for transactional email send.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../../core/errors'
import type { Channel } from '../../core/types/channel'

/**
 * Subset of the `resend` package surface we depend on. Both the v3
 * Resend client and any drop-in test double satisfies this.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface ResendClientLike {
  emails: {
    send(opts: {
      from: string
      to: string | string[]
      subject: string
      text?: string
      html?: string
      headers?: Record<string, string>
    }): Promise<{ data?: { id?: string } | null; error?: { message: string } | null }>
  }
}

/**
 * Template resolver. The auth lib hands `(templateId, vars)` to this
 * hook; the app returns the rendered email body. Apps own all template
 * content.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export type ResendTemplateResolver = (
  templateId: string,
  vars: Record<string, unknown>,
) => Promise<{ subject: string; text?: string; html?: string }> | { subject: string; text?: string; html?: string }

/**
 * Config knobs for `ResendChannel`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface ResendChannelConfig {
  /** Resend API key, e.g. `re_xxx`. Required when `client` is not supplied. */
  apiKey?: string
  /** Pre-constructed Resend-like client. Useful for tests + custom transports. */
  client?: ResendClientLike
  /** From: address. Must be on a verified Resend domain. */
  from: string
  /** Template resolver invoked per send. */
  templates: ResendTemplateResolver
  /** Identifier appearing in logs + diagnostics. Default `resend`. */
  id?: string
}

let _resendModule: { Resend: new (key: string) => ResendClientLike } | null = null
async function loadResend(): Promise<{ Resend: new (key: string) => ResendClientLike }> {
  if (_resendModule) return _resendModule
  try {
    const mod = (await import('resend' as string)) as {
      Resend: new (key: string) => ResendClientLike
    }
    _resendModule = mod
    return mod
  } catch {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail:
        'ResendChannel requires the `resend` peerDep. ' + 'Install via `bun add resend` (or `npm install resend`).',
    })
  }
}

/**
 * Resend channel implementation of `Channel.IChannel`. Reads the
 * recipient email from `input.identity.profile.email`; returns
 * ok:false (never throws) on any Resend error so the caller can retry
 * or escalate without the exception escaping the channel boundary.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class ResendChannel implements Channel.IChannel {
  readonly kind: Channel.Kind = 'email'
  readonly id: string
  private readonly _from: string
  private readonly _resolve: ResendTemplateResolver
  private _clientPromise: Promise<ResendClientLike> | null = null

  constructor(cfg: ResendChannelConfig) {
    if (!cfg.from) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'ResendChannel requires a non-empty `from` address (must be on a verified Resend domain)',
      })
    }
    if (!cfg.apiKey && !cfg.client) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'ResendChannel requires either an apiKey or a pre-built client',
      })
    }
    this._from = cfg.from
    this._resolve = cfg.templates
    this.id = cfg.id ?? 'resend'

    if (cfg.client) {
      this._clientPromise = Promise.resolve(cfg.client)
    } else if (cfg.apiKey) {
      const apiKey = cfg.apiKey
      this._clientPromise = loadResend().then(({ Resend }) => new Resend(apiKey))
    }
  }

  /**
   * Resolve the template, look up the recipient, hand the rendered
   * email to Resend.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async send(input: Channel.SendInput): Promise<Channel.SendResult> {
    const profile = input.identity.profile as { email?: string } | undefined
    const to = profile?.email
    if (!to) {
      return { ok: false, error: 'identity has no email; ResendChannel cannot deliver' }
    }
    let resolved: Awaited<ReturnType<ResendTemplateResolver>>
    try {
      resolved = await this._resolve(input.templateId, input.vars as Record<string, unknown>)
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
    if (!this._clientPromise) {
      return { ok: false, error: 'ResendChannel has no client (misconfigured)' }
    }
    try {
      const client = await this._clientPromise
      const response = await client.emails.send({
        from: this._from,
        to,
        subject: resolved.subject,
        ...(resolved.text !== undefined && { text: resolved.text }),
        ...(resolved.html !== undefined && { html: resolved.html }),
      })
      if (response.error) {
        return { ok: false, error: response.error.message }
      }
      const out: Channel.SendResult = { ok: true }
      if (response.data?.id !== undefined) out.providerMessageId = response.data.id
      return out
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
  }
}

/**
 * Namespace merge for `ResendChannel`. Co-locates config + helpers.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace ResendChannel {
  /** Alias for `ResendChannelConfig`. */
  export type IConfig = ResendChannelConfig
  /** Alias for `ResendClientLike`. */
  export type IClient = ResendClientLike
  /** Alias for `ResendTemplateResolver`. */
  export type ITemplateResolver = ResendTemplateResolver
}
