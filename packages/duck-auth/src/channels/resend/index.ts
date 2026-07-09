/**
 * Resend channel adapter. Wraps the Resend HTTP API via the `resend`
 * npm package (lazy peerDep) for transactional email send.
 */

import type { Channel } from '~/channels/channels.types'
import { getProfileString } from '~/core/credential-utils'
import { AuthError } from '~/core/errors'

export namespace AuthResendChannel {
  /**
   * Subset of the `resend` package surface we depend on. Both the v3
   * Resend client and any drop-in test double satisfies this.
   */
  export interface IClient {
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
   * hook; the app returns the rendered email body.
   */
  export type ITemplateResolver = (
    templateId: string,
    vars: Record<string, unknown>,
  ) => Promise<{ subject: string; text?: string; html?: string }> | { subject: string; text?: string; html?: string }

  /** Config knobs for {@link AuthResendChannel}. */
  export interface IConfig {
    /** Resend API key. Required when `client` is not supplied. */
    apiKey?: string
    /** Pre-constructed Resend-like client. Useful for tests + custom transports. */
    client?: IClient
    /** From: address. Must be on a verified Resend domain. */
    from: string
    /** Template resolver invoked per send. */
    templates: ITemplateResolver
    /** Identifier appearing in logs + diagnostics. Default `resend`. */
    id?: string
  }
}

let _resendModule: { Resend: new (key: string) => AuthResendChannel.IClient } | null = null
async function loadResend(): Promise<{ Resend: new (key: string) => AuthResendChannel.IClient }> {
  if (_resendModule) return _resendModule
  try {
    const mod = await import('resend' as string)
    _resendModule = mod
    return mod
  } catch {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail:
        'AuthResendChannel requires the `resend` peerDep. Install via `bun add resend` (or `npm install resend`).',
    })
  }
}

/**
 * Resend channel implementation of `Channel.IChannel`. Reads the
 * recipient email from `input.identity.profile.email`; returns
 * ok:false (never throws) on any Resend error.
 */
export class AuthResendChannel implements Channel.Channel {
  readonly kind: Channel.Kind = 'email'
  readonly id: string
  private readonly _from: string
  private readonly _resolve: AuthResendChannel.ITemplateResolver
  private _clientPromise: Promise<AuthResendChannel.IClient> | null = null

  constructor(cfg: AuthResendChannel.IConfig) {
    if (!cfg.from) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthResendChannel requires a non-empty `from` address (must be on a verified Resend domain)',
      })
    }
    if (!cfg.apiKey && !cfg.client) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthResendChannel requires either an apiKey or a pre-built client',
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
   */
  async send(input: Channel.SendInput): Promise<Channel.SendResult> {
    const to = getProfileString(input.identity.profile, 'email')
    if (!to) {
      return { ok: false, error: 'identity has no email; AuthResendChannel cannot deliver' }
    }
    let resolved: Awaited<ReturnType<AuthResendChannel.ITemplateResolver>>
    try {
      resolved = await this._resolve(input.templateId, input.vars)
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
    if (!this._clientPromise) {
      return { ok: false, error: 'AuthResendChannel has no client (misconfigured)' }
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
