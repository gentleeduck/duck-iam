/**
 * @packageDocumentation
 * Twilio SMS channel adapter. Wraps the official `twilio` SDK
 * (lazy peerDep) for kind:'sms' message delivery. Recipient phone
 * number is read from `identity.profile.phone`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../../core/errors'
import type { Channel } from '../../core/types/channel'

/**
 * Subset of the Twilio SDK we depend on. Mirrors `messages.create`
 * (the only call we make). Tests + custom transports satisfy this
 * shape without pulling in the full SDK.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface TwilioClientLike {
  messages: {
    create(opts: {
      from?: string
      messagingServiceSid?: string
      to: string
      body: string
    }): Promise<{ sid?: string; errorCode?: number | null; errorMessage?: string | null }>
  }
}

/**
 * Template resolver. Returns the rendered SMS body for a given
 * `(templateId, vars)`. Apps own all template content.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export type TwilioTemplateResolver = (
  templateId: string,
  vars: Record<string, unknown>,
) => Promise<{ body: string }> | { body: string }

/**
 * Config knobs for `TwilioChannel`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface TwilioChannelConfig {
  /** Twilio Account SID. Required when `client` is not supplied. */
  accountSid?: string
  /** Twilio Auth Token. Required when `client` is not supplied. */
  authToken?: string
  /** Pre-built Twilio client. Useful for tests + custom transports. */
  client?: TwilioClientLike
  /**
   * Either a `from` phone number OR a `messagingServiceSid`. Exactly
   * one must be present; Twilio rejects the request otherwise.
   */
  from?: string
  messagingServiceSid?: string
  /** Template resolver invoked per send. */
  templates: TwilioTemplateResolver
  /** Identifier appearing in logs + diagnostics. Default `twilio`. */
  id?: string
}

let _twilioModule: { default: (sid: string, token: string) => TwilioClientLike } | null = null
async function loadTwilio(): Promise<(sid: string, token: string) => TwilioClientLike> {
  if (_twilioModule) return _twilioModule.default
  try {
    const mod = (await import('twilio' as string)) as {
      default: (sid: string, token: string) => TwilioClientLike
    }
    _twilioModule = mod
    return mod.default
  } catch {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail:
        'TwilioChannel requires the `twilio` peerDep. ' + 'Install via `bun add twilio` (or `npm install twilio`).',
    })
  }
}

/**
 * Twilio SMS channel. Reads recipient phone from
 * `identity.profile.phone`; returns ok:false (never throws) on any
 * Twilio error so the caller can retry or escalate without exception
 * escape.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class TwilioChannel implements Channel.IChannel {
  readonly kind: Channel.Kind = 'sms'
  readonly id: string
  private readonly _from: string | undefined
  private readonly _msgServiceSid: string | undefined
  private readonly _resolve: TwilioTemplateResolver
  private _clientPromise: Promise<TwilioClientLike> | null = null

  constructor(cfg: TwilioChannelConfig) {
    if (!cfg.from && !cfg.messagingServiceSid) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'TwilioChannel requires either `from` or `messagingServiceSid`',
      })
    }
    if (cfg.from && cfg.messagingServiceSid) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'TwilioChannel: pass exactly one of `from` or `messagingServiceSid`, not both',
      })
    }
    if (!cfg.client && (!cfg.accountSid || !cfg.authToken)) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'TwilioChannel requires either { accountSid + authToken } or a pre-built client',
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

  /**
   * Render the template, send via Twilio. Returns ok:false on any
   * error surface (missing phone, template resolver throw, Twilio
   * errorCode, network throw). Never throws.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async send(input: Channel.SendInput): Promise<Channel.SendResult> {
    const profile = input.identity.profile as { phone?: string } | undefined
    const to = profile?.phone
    if (!to) {
      return { ok: false, error: 'identity has no phone; TwilioChannel cannot deliver' }
    }
    let resolved: Awaited<ReturnType<TwilioTemplateResolver>>
    try {
      resolved = await this._resolve(input.templateId, input.vars as Record<string, unknown>)
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
    if (!this._clientPromise) {
      return { ok: false, error: 'TwilioChannel has no client (misconfigured)' }
    }
    try {
      const client = await this._clientPromise
      const opts: Parameters<TwilioClientLike['messages']['create']>[0] = {
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

/**
 * Namespace merge for `TwilioChannel`. Co-locates config + helpers.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace TwilioChannel {
  /** Alias for `TwilioChannelConfig`. */
  export type IConfig = TwilioChannelConfig
  /** Alias for `TwilioClientLike`. */
  export type IClient = TwilioClientLike
  /** Alias for `TwilioTemplateResolver`. */
  export type ITemplateResolver = TwilioTemplateResolver
}
