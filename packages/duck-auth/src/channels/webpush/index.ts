/**
 * Web Push channel adapter. Wraps the `web-push` library (lazy peerDep)
 * for kind:'webpush' delivery. Caller's identity profile MUST carry a
 * `pushSubscription` field with the standard VAPID-compatible shape.
 */

import type { Channel } from '~/channels/channels.types'
import { AuthError } from '~/core/errors'

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

  /** Subset of the `web-push` library we depend on. */
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

  /** Cfg knobs for {@link AuthWebPushChannel}. */
  export interface Cfg {
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

  constructor(cfg: AuthWebPushChannel.Cfg) {
    if (!cfg.subject || !cfg.publicKey || !cfg.privateKey) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthWebPushChannel requires subject + publicKey + privateKey (VAPID details)',
      })
    }
    this._cfg = cfg
    this.id = cfg.id ?? 'web-push'
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
      return { ok: false, error: 'identity has no pushSubscription; AuthWebPushChannel cannot deliver' }
    }
    let resolved: Awaited<ReturnType<AuthWebPushChannel.ITemplateResolver>>
    try {
      resolved = await this._cfg.templates(input.templateId, input.vars)
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

/** Factory around {@link AuthWebPushChannel}, for callers who prefer functions to `new`. */
export function authWebPushChannel(...args: ConstructorParameters<typeof AuthWebPushChannel>): AuthWebPushChannel {
  return new AuthWebPushChannel(...args)
}
