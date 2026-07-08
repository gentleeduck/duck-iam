/**
 * Twilio SMS channel adapter. Wraps the official `twilio` SDK
 * (lazy peerDep) for kind:'sms' message delivery. Recipient phone
 * number is read from `identity.profile.phone`.
 */

import { getProfileString } from '~/core/credential-utils'
import { AuthError } from '~/core/errors'
import type { Channel } from '~/core/types/infra'

export namespace AuthTwilioChannel {
  /** Subset of the Twilio SDK we depend on. */
  export interface IClient {
    messages: {
      create(opts: {
        from?: string
        messagingServiceSid?: string
        to: string
        body: string
      }): Promise<{ sid?: string; errorCode?: number | null; errorMessage?: string | null }>
    }
  }

  /** Template resolver. Returns the rendered SMS body. */
  export type ITemplateResolver = (
    templateId: string,
    vars: Record<string, unknown>,
  ) => Promise<{ body: string }> | { body: string }

  /** Config knobs for {@link AuthTwilioChannel}. */
  export interface IConfig {
    /** Twilio Account SID. Required when `client` is not supplied. */
    accountSid?: string
    /** Twilio Auth Token. Required when `client` is not supplied. */
    authToken?: string
    /** Pre-built Twilio client. Useful for tests + custom transports. */
    client?: IClient
    /**
     * Either a `from` phone number OR a `messagingServiceSid`. Exactly
     * one must be present; Twilio rejects the request otherwise.
     */
    from?: string
    messagingServiceSid?: string
    /** Template resolver invoked per send. */
    templates: ITemplateResolver
    /** Identifier appearing in logs + diagnostics. Default `twilio`. */
    id?: string
  }
}

let _twilioModule: { default: (sid: string, token: string) => AuthTwilioChannel.IClient } | null = null
async function loadTwilio(): Promise<(sid: string, token: string) => AuthTwilioChannel.IClient> {
  if (_twilioModule) return _twilioModule.default
  try {
    const mod = await import('twilio' as string)
    _twilioModule = mod
    return mod.default
  } catch {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail:
        'AuthTwilioChannel requires the `twilio` peerDep. Install via `bun add twilio` (or `npm install twilio`).',
    })
  }
}

/**
 * Twilio SMS channel. Reads recipient phone from
 * `identity.profile.phone`; returns ok:false on any Twilio error.
 */
export class AuthTwilioChannel implements Channel.Channel {
  readonly kind: Channel.Kind = 'sms'
  readonly id: string
  private readonly _from: string | undefined
  private readonly _msgServiceSid: string | undefined
  private readonly _resolve: AuthTwilioChannel.ITemplateResolver
  private _clientPromise: Promise<AuthTwilioChannel.IClient> | null = null

  constructor(cfg: AuthTwilioChannel.IConfig) {
    if (!cfg.from && !cfg.messagingServiceSid) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthTwilioChannel requires either `from` or `messagingServiceSid`',
      })
    }
    if (cfg.from && cfg.messagingServiceSid) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthTwilioChannel: pass exactly one of `from` or `messagingServiceSid`, not both',
      })
    }
    if (!cfg.client && (!cfg.accountSid || !cfg.authToken)) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthTwilioChannel requires either { accountSid + authToken } or a pre-built client',
      })
    }
    this._from = cfg.from
    this._msgServiceSid = cfg.messagingServiceSid
    this._resolve = cfg.templates
    this.id = cfg.id ?? 'twilio'

    if (cfg.client) {
      this._clientPromise = Promise.resolve(cfg.client)
    } else if (cfg.accountSid && cfg.authToken) {
      const sid = cfg.accountSid
      const token = cfg.authToken
      this._clientPromise = loadTwilio().then((factory) => factory(sid, token))
    }
  }

  /** Render template, send via Twilio. Returns ok:false on any error. */
  async send(input: Channel.SendInput): Promise<Channel.SendResult> {
    const to = getProfileString(input.identity.profile, 'phone')
    if (!to) {
      return { ok: false, error: 'identity has no phone; AuthTwilioChannel cannot deliver' }
    }
    let resolved: Awaited<ReturnType<AuthTwilioChannel.ITemplateResolver>>
    try {
      resolved = await this._resolve(input.templateId, input.vars)
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
    if (!this._clientPromise) {
      return { ok: false, error: 'AuthTwilioChannel has no client (misconfigured)' }
    }
    try {
      const client = await this._clientPromise
      const opts: Parameters<AuthTwilioChannel.IClient['messages']['create']>[0] = {
        to,
        body: resolved.body,
      }
      if (this._from) opts.from = this._from
      if (this._msgServiceSid) opts.messagingServiceSid = this._msgServiceSid
      const response = await client.messages.create(opts)
      if (response.errorCode) {
        return { ok: false, error: response.errorMessage ?? `twilio error ${response.errorCode}` }
      }
      const out: Channel.SendResult = { ok: true }
      if (response.sid !== undefined) out.providerMessageId = response.sid
      return out
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
  }
}
