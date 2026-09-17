/**
 * Twilio SMS channel adapter. Wraps the official `twilio` SDK
 * (lazy peerDep) for kind:'sms' message delivery. Recipient phone
 * number is read from `identity.profile.phone`.
 */

import type { Channel } from '~/channels/channels.types'
import { AuthError } from '~/core/errors'
import { ChannelGuard } from '../channels.guard'
import {
  checkRenderedSms,
  describeSendError,
  redactProviderError,
  resolvePhoneRecipient,
  SMS_BODY_MAX_LENGTH,
} from '../channels.outbound'

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

  /** Cfg knobs for {@link AuthTwilioChannel}. */
  export interface Cfg extends ChannelGuard.Cfg {
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
  private readonly _guard: ChannelGuard

  constructor(cfg: AuthTwilioChannel.Cfg) {
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
    this._guard = new ChannelGuard(this.id, cfg)

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
    const recipient = resolvePhoneRecipient(input.identity.profile, 'AuthTwilioChannel')
    if (!recipient.ok) return { error: recipient.error, ok: false, retryable: false }
    const denied = await this._guard.spend(input)
    if (denied) return { error: denied, ok: false, retryable: true }
    const to = recipient.to
    let resolved: Awaited<ReturnType<AuthTwilioChannel.ITemplateResolver>>
    try {
      resolved = await this._resolve(input.templateId, input.vars)
    } catch (err) {
      return { error: describeSendError(err), ok: false, retryable: false }
    }
    const malformed = checkRenderedSms(resolved)
    if (malformed) return { error: `AuthTwilioChannel: ${malformed}`, ok: false, retryable: false }
    if (!this._clientPromise) {
      return { error: 'AuthTwilioChannel has no client (misconfigured)', ok: false, retryable: false }
    }
    try {
      const client = await this._clientPromise
      const opts: Parameters<AuthTwilioChannel.IClient['messages']['create']>[0] = {
        to,
        // Capped, not forwarded: a resolver interpolating an attacker-influenced variable into an
        // SMS turns one send into thousands of billed segments.
        body: resolved.body.slice(0, SMS_BODY_MAX_LENGTH),
      }
      if (this._from) opts.from = this._from
      if (this._msgServiceSid) opts.messagingServiceSid = this._msgServiceSid
      const response = await this._guard.attempt(() => client.messages.create(opts))
      if (response.errorCode) {
        return {
          error: redactProviderError(response.errorMessage ?? `twilio error ${response.errorCode}`),
          ok: false,
          retryable: true,
        }
      }
      const out: Channel.SendResult = { ok: true }
      if (response.sid !== undefined) out.providerMessageId = response.sid
      return out
    } catch (err) {
      return { error: describeSendError(err), ok: false, retryable: true }
    }
  }
}

/** Factory around {@link AuthTwilioChannel}, for callers who prefer functions to `new`. */
export function authTwilioChannel(...args: ConstructorParameters<typeof AuthTwilioChannel>): AuthTwilioChannel {
  return new AuthTwilioChannel(...args)
}
