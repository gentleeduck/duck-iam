/**
 * @packageDocumentation
 * Web Push channel adapter. Wraps the `web-push` library (lazy peerDep)
 * for kind:'webpush' delivery. Caller's identity profile MUST carry a
 * `pushSubscription` field with the standard VAPID-compatible shape
 * the browser produces from `pushManager.subscribe()`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../../core/errors'
import type { Channel } from '../../core/types/channel'

/**
 * Standard Push API subscription shape - what the browser hands the
 * server after `pushManager.subscribe({ userVisibleOnly, applicationServerKey })`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface PushSubscriptionShape {
  endpoint: string
  expirationTime?: number | null
  keys: {
    p256dh: string
    auth: string
  }
}

/**
 * Subset of the `web-push` library we depend on. The real library
 * exports `setVapidDetails` + `sendNotification`; we call both.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface WebPushModuleLike {
  setVapidDetails(subject: string, publicKey: string, privateKey: string): void
  sendNotification(
    subscription: PushSubscriptionShape,
    payload: string,
    opts?: { TTL?: number; urgency?: 'very-low' | 'low' | 'normal' | 'high' },
  ): Promise<{ statusCode?: number; headers?: Record<string, string> }>
}

/**
 * Template resolver. Returns the rendered notification payload for a
 * `(templateId, vars)` pair. The body must be a string (typically JSON
 * encoded) - the worker on the client side will parse it.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export type WebPushTemplateResolver = (
  templateId: string,
  vars: Record<string, unknown>,
) => Promise<{ payload: string; ttl?: number }> | { payload: string; ttl?: number }

/**
 * Config knobs for `WebPushChannel`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface WebPushChannelConfig {
  /** VAPID subject; either an HTTPS URL or a mailto: URI. Required. */
  subject: string
  /** VAPID public key (base64url). Required. */
  publicKey: string
  /** VAPID private key (base64url). Required. */
  privateKey: string
  /** Pre-built web-push-like module (tests). Otherwise lazy-loaded. */
  module?: WebPushModuleLike
  /** Template resolver invoked per send. */
  templates: WebPushTemplateResolver
  /** Identifier in logs + diagnostics. Default `web-push`. */
  id?: string
}

let _module: WebPushModuleLike | null = null
async function loadWebPush(override?: WebPushModuleLike): Promise<WebPushModuleLike> {
  if (override) return override
  if (_module) return _module
  try {
    const mod = (await import('web-push' as string)) as unknown as WebPushModuleLike | { default: WebPushModuleLike }
    const resolved = 'default' in mod ? mod.default : mod
    _module = resolved
    return resolved
  } catch {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail:
        'WebPushChannel requires the `web-push` peerDep. ' +
        'Install via `bun add web-push` (or `npm install web-push`).',
    })
  }
}

/**
 * Web Push channel. Reads the recipient's `pushSubscription` from the
 * identity profile; returns ok:false (never throws) on any web-push
 * error. The classic `410 Gone` response (subscription expired) is
 * surfaced verbatim so the caller can prune the dead subscription.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class WebPushChannel implements Channel.IChannel {
  readonly kind: Channel.Kind = 'webpush'
  readonly id: string
  private readonly _cfg: WebPushChannelConfig
  private _modulePromise: Promise<WebPushModuleLike> | null = null

  constructor(cfg: WebPushChannelConfig) {
    if (!cfg.subject || !cfg.publicKey || !cfg.privateKey) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'WebPushChannel requires subject + publicKey + privateKey (VAPID details)',
      })
    }
    this._cfg = cfg
    this.id = cfg.id ?? 'web-push'
  }

  /** Lazy-load + configure VAPID once per process. */
  private async _module(): Promise<WebPushModuleLike> {
    if (this._modulePromise) return this._modulePromise
    this._modulePromise = loadWebPush(this._cfg.module).then((mod) => {
      mod.setVapidDetails(this._cfg.subject, this._cfg.publicKey, this._cfg.privateKey)
      return mod
    })
    return this._modulePromise
  }

  /**
   * Resolve the template, look up the subscription, hand it to
   * web-push. Returns ok:false on any error (missing subscription,
   * template throw, web-push error, network).
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async send(input: Channel.SendInput): Promise<Channel.SendResult> {
    const profile = input.identity.profile as { pushSubscription?: PushSubscriptionShape } | undefined
    const subscription = profile?.pushSubscription
    if (!subscription?.endpoint || !subscription.keys?.p256dh || !subscription.keys?.auth) {
      return { ok: false, error: 'identity has no pushSubscription; WebPushChannel cannot deliver' }
    }
    let resolved: Awaited<ReturnType<WebPushTemplateResolver>>
    try {
      resolved = await this._cfg.templates(input.templateId, input.vars as Record<string, unknown>)
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
    try {
      const mod = await this._module()
      const response = await mod.sendNotification(subscription, resolved.payload, {
        ...(resolved.ttl !== undefined && { TTL: resolved.ttl }),
      })
      const out: Channel.SendResult = { ok: true }
      if (response.statusCode !== undefined) {
        out.providerMessageId = `webpush:${response.statusCode}`
      }
      return out
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      const statusCode = (err as { statusCode?: number }).statusCode
      const composed = statusCode ? `${statusCode}:${message}` : message
      return { ok: false, error: composed }
    }
  }
}

/**
 * Namespace merge for `WebPushChannel`. Co-locates config + module
 * + subscription types alongside the class.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace WebPushChannel {
  /** Alias for `WebPushChannelConfig`. */
  export type IConfig = WebPushChannelConfig
  /** Alias for `WebPushModuleLike`. */
  export type IModule = WebPushModuleLike
  /** Alias for `PushSubscriptionShape`. */
  export type ISubscription = PushSubscriptionShape
  /** Alias for `WebPushTemplateResolver`. */
  export type ITemplateResolver = WebPushTemplateResolver
}
