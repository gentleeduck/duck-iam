/**
 * @packageDocumentation
 * Webhook delivery for the Events bus. Subscribes to selected events,
 * forwards each emission to N consumer URLs over HTTPS with an HMAC
 * signature, exponential-backoff retry, and a dead-letter sink.
 *
 * Auth lib intentionally stays out of the consumer-side webhook
 * registration UX; this class accepts the endpoint set up front. Apps
 * that want a self-service webhook UI wire their own table + reload
 * the subscriber on change.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { createHmac, timingSafeEqual } from 'node:crypto'
import { AuthErrorObject } from '../errors'
import type { Events } from '../types/events'

/**
 * Per-endpoint webhook subscription. Each delivery is HMAC-signed with
 * `secret`; consumer verifies via the matching key.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface WebhookEndpoint {
  /** Absolute HTTPS URL. */
  url: string
  /** Shared secret; signs the HMAC header. Treat as confidential. */
  secret: string
  /** Event names this endpoint receives. Default `'*'` -> every event. */
  events?: Events.EventName[] | '*'
  /** Header name carrying the HMAC. Default `'X-Duck-Signature'`. */
  signatureHeader?: string
  /**
   * Caller-supplied identifier for the endpoint (UI labels, audit
   * logs). Default `url`.
   */
  id?: string
}

/**
 * Sink for permanently-failed deliveries (retries exhausted). Apps
 * wire a Redis list / SQL table / Slack-alert channel here so the ops
 * team can replay or investigate.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface WebhookDeadLetterSink {
  put(envelope: WebhookDeadLetterEntry): Promise<void>
}

/** Shape persisted in the dead-letter sink. */
export interface WebhookDeadLetterEntry {
  endpointId: string
  endpointUrl: string
  eventName: Events.EventName
  payload: unknown
  attempts: number
  lastError: string
  firstAttemptAt: number
  lastAttemptAt: number
}

/**
 * Config for `WebhookDeliverer`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface WebhookDelivererConfig {
  endpoints: WebhookEndpoint[]
  /** Maximum delivery attempts before dead-lettering. Default 5. */
  maxAttempts?: number
  /** Base backoff in ms (exponential). Default 500ms (so 0.5s, 1s, 2s, 4s, 8s). */
  backoffMs?: number
  /** Request timeout per delivery, ms. Default 5_000. */
  timeoutMs?: number
  /** Override fetch impl (tests). */
  fetch?: typeof globalThis.fetch
  /** Sink for permanently-failed deliveries. */
  deadLetter?: WebhookDeadLetterSink
}

/**
 * Subscribe the bus, sign + POST each emit to the configured endpoints,
 * retry with exponential backoff, dead-letter on permanent failure.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class WebhookDeliverer {
  private readonly _endpoints: Required<Omit<WebhookEndpoint, 'events' | 'signatureHeader' | 'id'>> &
    {
      events: Events.EventName[] | '*'
      signatureHeader: string
      id: string
    }[]
  private readonly _maxAttempts: number
  private readonly _backoffMs: number
  private readonly _timeoutMs: number
  private readonly _fetch: typeof globalThis.fetch
  private readonly _deadLetter: WebhookDeadLetterSink | undefined

  constructor(cfg: WebhookDelivererConfig) {
    if (!cfg.endpoints?.length) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'WebhookDeliverer requires at least one endpoint',
      })
    }
    for (const e of cfg.endpoints) {
      if (!e.url || !e.secret) {
        throw new AuthErrorObject('AUTH/MISCONFIGURED', {
          detail: 'WebhookDeliverer endpoint requires both url + secret',
        })
      }
    }
    this._endpoints = cfg.endpoints.map((e) => ({
      url: e.url,
      secret: e.secret,
      events: e.events ?? '*',
      signatureHeader: e.signatureHeader ?? 'X-Duck-Signature',
      id: e.id ?? e.url,
    })) as never
    this._maxAttempts = cfg.maxAttempts ?? 5
    this._backoffMs = cfg.backoffMs ?? 500
    this._timeoutMs = cfg.timeoutMs ?? 5_000
    this._fetch = cfg.fetch ?? globalThis.fetch
    this._deadLetter = cfg.deadLetter
  }

  /**
   * Attach to every relevant event on the bus. Returns a cleanup that
   * detaches every listener.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  attach(bus: Events.IBus): () => void {
    // Collect the union of subscribed event names across all endpoints.
    const allNames = new Set<Events.EventName>()
    for (const e of this._endpoints as unknown as Array<{ events: Events.EventName[] | '*' }>) {
      if (e.events === '*') {
        for (const n of EVERY_EVENT) allNames.add(n)
      } else {
        for (const n of e.events) allNames.add(n)
      }
    }
    const subs: Events.Unsubscribe[] = []
    for (const name of allNames) {
      subs.push(
        bus.on(name, async (payload) => {
          await this.deliverOne(name, payload as unknown)
        }),
      )
    }
    return () => {
      for (const off of subs) off()
    }
  }

  /**
   * Public for tests + manual re-deliveries. Drives the per-endpoint
   * fanout + retry loop for a single (name, payload) pair.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async deliverOne(name: Events.EventName, payload: unknown): Promise<void> {
    const eligible = (
      this._endpoints as unknown as Array<{
        url: string
        secret: string
        events: Events.EventName[] | '*'
        signatureHeader: string
        id: string
      }>
    ).filter((e) => e.events === '*' || e.events.includes(name))
    await Promise.all(eligible.map((e) => this._deliverWithRetry(name, payload, e)))
  }

  private async _deliverWithRetry(
    name: Events.EventName,
    payload: unknown,
    endpoint: {
      url: string
      secret: string
      signatureHeader: string
      id: string
    },
  ): Promise<void> {
    const firstAttemptAt = Date.now()
    let lastError = ''
    let attempt = 0
    while (attempt < this._maxAttempts) {
      attempt++
      try {
        const ok = await this._dispatch(name, payload, endpoint)
        if (ok) return
        lastError = 'non-2xx response'
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err)
      }
      if (attempt < this._maxAttempts) {
        const wait = this._backoffMs * 2 ** (attempt - 1)
        await new Promise((r) => setTimeout(r, wait))
      }
    }
    if (this._deadLetter) {
      await this._deadLetter
        .put({
          endpointId: endpoint.id,
          endpointUrl: endpoint.url,
          eventName: name,
          payload,
          attempts: attempt,
          lastError,
          firstAttemptAt,
          lastAttemptAt: Date.now(),
        })
        .catch(() => {
          // Dead-letter sink failure is non-fatal; log + drop.
        })
    }
  }

  private async _dispatch(
    name: Events.EventName,
    payload: unknown,
    endpoint: { url: string; secret: string; signatureHeader: string },
  ): Promise<boolean> {
    const body = JSON.stringify({ event: name, payload, timestamp: Date.now() })
    const signature = signWebhookBody(endpoint.secret, body)
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this._timeoutMs)
    try {
      const res = await this._fetch(endpoint.url, {
        method: 'POST',
        body,
        headers: {
          'content-type': 'application/json',
          [endpoint.signatureHeader]: signature,
          'user-agent': '@gentleduck/auth-webhook',
        },
        signal: controller.signal,
      })
      return res.ok
    } finally {
      clearTimeout(timer)
    }
  }
}

/**
 * Sign a webhook body for transport. Caller-side consumers verify via
 * `verifyWebhookSignature`. Algorithm: `sha256=` + lowercase hex
 * digest, matching the convention most webhook tooling uses.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function signWebhookBody(secret: string, body: string): string {
  return `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`
}

/**
 * Constant-time verify a webhook signature against the raw body. Apps
 * call this in their handler before parsing the JSON.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function verifyWebhookSignature(secret: string, body: string, signature: string): boolean {
  const expected = signWebhookBody(secret, body)
  const a = Buffer.from(signature)
  const b = Buffer.from(expected)
  return a.length === b.length && timingSafeEqual(a, b)
}

/** Every event name in the Events.EventMap; used to materialize `'*'` subscriptions. */
const EVERY_EVENT: Events.EventName[] = [
  'session.created',
  'session.rotated',
  'session.revoked',
  'signin.success',
  'signin.failed',
  'signup.completed',
  'lockout',
  'mfa.enrolled',
  'mfa.removed',
  'identity.linked',
  'identity.merged',
  'identity.impersonated',
  'recovery.password.requested',
  'recovery.password.completed',
  'recovery.mfa.escalated',
  'suspicious',
  'maintenance.on',
  'maintenance.off',
]

/**
 * Namespace merge for the webhook surface.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace WebhookDeliverer {
  /** Alias for `WebhookDelivererConfig`. */
  export type IConfig = WebhookDelivererConfig
  /** Alias for `WebhookEndpoint`. */
  export type IEndpoint = WebhookEndpoint
  /** Alias for `WebhookDeadLetterSink`. */
  export type IDeadLetterSink = WebhookDeadLetterSink
  /** Alias for `WebhookDeadLetterEntry`. */
  export type IDeadLetterEntry = WebhookDeadLetterEntry
}
