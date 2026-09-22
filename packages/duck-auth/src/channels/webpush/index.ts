/**
 * Web Push channel adapter. Wraps the `web-push` library (lazy peerDep)
 * for kind:'webpush' delivery. Caller's identity profile MUST carry a
 * `pushSubscription` field with the standard VAPID-compatible shape.
 */

import type { Channel } from '~/channels/channels.types'
import { AuthError } from '~/core/errors'
import { assertSafeOutboundUrl } from '~/core/url-validators'
import { ChannelGuard } from '../channels.guard'
import { describeSendError } from '../channels.outbound'

/** RFC 8291: an encrypted push payload is at most 4096 octets, and push services refuse more. */
const PAYLOAD_MAX_BYTES = 4096

export namespace AuthWebPushChannel {
  /** Standard Push API subscription shape. */
  export interface ISubscription {
    endpoint: string
    expirationTime?: number | null
    keys: {
      p256dh: string
      auth: string
    }
  }

  /** The subset of the `web-push` library this uses. */
  export interface IModule {
    setVapidDetails(subject: string, publicKey: string, privateKey: string): void
    sendNotification(
      subscription: ISubscription,
      payload: string,
      opts?: { TTL?: number; urgency?: 'very-low' | 'low' | 'normal' | 'high' },
    ): Promise<{ statusCode?: number; headers?: Record<string, string> }>
  }

  /** Template resolver. Returns the rendered notification payload. */
  export type ITemplateResolver = (
    templateId: string,
    vars: Record<string, unknown>,
  ) => Promise<{ payload: string; ttl?: number }> | { payload: string; ttl?: number }

  export interface Cfg extends ChannelGuard.Cfg {
    /** VAPID subject (HTTPS URL or mailto: URI). Required. */
    subject: string
    /** VAPID public key (base64url). Required. */
    publicKey: string
    /** VAPID private key (base64url). Required. */
    privateKey: string
    /** Pre-built web-push-like module (tests). Otherwise lazy-loaded. */
    module?: IModule
    /** Template resolver invoked per send. */
    templates: ITemplateResolver
    /** Identifier in logs + diagnostics. Default `web-push`. */
    id?: string
  }
}

let _module: AuthWebPushChannel.IModule | null = null
async function loadWebPush(override?: AuthWebPushChannel.IModule): Promise<AuthWebPushChannel.IModule> {
  if (override) return override
  if (_module) return _module
  try {
    const mod = await import('web-push' as string)
    const resolved = 'default' in mod ? mod.default : mod
    _module = resolved
    return resolved
  } catch {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail:
        'AuthWebPushChannel requires the `web-push` peerDep. Install via `bun add web-push` (or `npm install web-push`).',
    })
  }
}

/**
 * Web Push channel. Reads `pushSubscription` from the identity
 * profile; returns ok:false on any error.
 */
export class AuthWebPushChannel implements Channel.Channel {
  readonly kind: Channel.Kind = 'webpush'
  readonly id: string
  private readonly _cfg: AuthWebPushChannel.Cfg
  private _modulePromise: Promise<AuthWebPushChannel.IModule> | null = null
  private readonly _guard: ChannelGuard

  constructor(cfg: AuthWebPushChannel.Cfg) {
    if (!cfg.subject || !cfg.publicKey || !cfg.privateKey) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthWebPushChannel requires subject + publicKey + privateKey (VAPID details)',
      })
    }
    this._cfg = cfg
    this.id = cfg.id ?? 'web-push'
    this._guard = new ChannelGuard(this.id, cfg)
  }

  /** Lazy-load + configure VAPID once per process. */
  private async _module(): Promise<AuthWebPushChannel.IModule> {
    if (this._modulePromise) return this._modulePromise
    this._modulePromise = loadWebPush(this._cfg.module).then((mod) => {
      mod.setVapidDetails(this._cfg.subject, this._cfg.publicKey, this._cfg.privateKey)
      return mod
    })
    return this._modulePromise
  }

  /**
   * Resolve template, look up subscription, hand to web-push. Returns
   * ok:false on any error (missing subscription, template throw,
   * web-push error, network).
   */
  async send(input: Channel.SendInput): Promise<Channel.SendResult> {
    const profile = input.identity.profile as { pushSubscription?: AuthWebPushChannel.ISubscription } | undefined
    const subscription = profile?.pushSubscription
    if (!subscription?.endpoint || !subscription.keys?.p256dh || !subscription.keys?.auth) {
      return {
        error: 'identity has no pushSubscription; AuthWebPushChannel cannot deliver',
        ok: false,
        retryable: false,
      }
    }
    // The endpoint is a URL this process will POST to, held on a user-editable profile field, so it
    // gets the same treatment as a webhook endpoint rather than none.
    try {
      assertSafeOutboundUrl(subscription.endpoint, { label: 'AuthWebPushChannel subscription endpoint' })
    } catch (err) {
      return { error: describeSendError(err), ok: false, retryable: false }
    }
    const budget = await this._guard.spend(input).wrap()
    if (budget.error) return { error: budget.error.code, ok: false, retryable: true }
    let resolved: Awaited<ReturnType<AuthWebPushChannel.ITemplateResolver>>
    try {
      resolved = await this._cfg.templates(input.templateId, input.vars)
    } catch (err) {
      return { error: describeSendError(err), ok: false, retryable: false }
    }
    const size = Buffer.byteLength(resolved.payload)
    if (size > PAYLOAD_MAX_BYTES) {
      return {
        error: `AuthWebPushChannel: payload is ${size} bytes, over the ${PAYLOAD_MAX_BYTES} a push service accepts`,
        ok: false,
        retryable: false,
      }
    }
    try {
      const mod = await this._module()
      const response = await this._guard.attempt(() =>
        mod.sendNotification(subscription, resolved.payload, {
          ...(resolved.ttl !== undefined && { TTL: resolved.ttl }),
        }),
      )
      const out: Channel.SendResult = { ok: true }
      if (response.statusCode !== undefined) {
        out.providerMessageId = `webpush:${response.statusCode}`
      }
      return out
    } catch (err) {
      const statusCode = (err as { statusCode?: number }).statusCode
      const message = describeSendError(err)
      return { error: statusCode ? `${statusCode}:${message}` : message, ok: false, retryable: true }
    }
  }
}

/** Web Push channel over VAPID. */
export function authWebPushChannel(...args: ConstructorParameters<typeof AuthWebPushChannel>): AuthWebPushChannel {
  return new AuthWebPushChannel(...args)
}
