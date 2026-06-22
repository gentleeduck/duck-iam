/**
 * Webhook delivery for the AuthEvents bus. Subscribes to selected events,
 * forwards each emission to N consumer URLs over HTTPS with an HMAC
 * signature, exponential-backoff retry, and a dead-letter sink.
 *
 * Auth lib intentionally stays out of the consumer-side webhook
 * registration UX; this class accepts the endpoint set up front. Apps
 * that want a self-service webhook UI wire their own table + reload
 * the subscriber on change.
 */

import { createHmac, timingSafeEqual } from 'node:crypto'
import { AuthErrorObject } from '../errors'
import type { AuthEvents } from '../types/events'

/**
 * Subscribe the bus, sign + POST each emit to the configured endpoints,
 * retry with exponential backoff, dead-letter on permanent failure.
 */
export class AuthWebhookDeliverer {
  private readonly _endpoints: Array<
    Required<Omit<AuthWebhookDeliverer.IEndpoint, 'events' | 'signatureHeader' | 'id'>> & {
      events: AuthEvents.EventName[] | '*'
      signatureHeader: string
      id: string
    }
  >
  private readonly _maxAttempts: number
  private readonly _backoffMs: number
  private readonly _timeoutMs: number
  private readonly _fetch: typeof globalThis.fetch
  private readonly _deadLetter: AuthWebhookDeliverer.IDeadLetterSink | undefined

  constructor(cfg: AuthWebhookDeliverer.IConfig) {
    if (!cfg.endpoints?.length) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'AuthWebhookDeliverer requires at least one endpoint',
      })
    }
    for (const e of cfg.endpoints) {
      if (!e.url || !e.secret) {
        throw new AuthErrorObject('AUTH/MISCONFIGURED', {
          detail: 'AuthWebhookDeliverer endpoint requires both url + secret',
        })
      }
      // SSRF guard; rejects non-HTTPS + loopback/private/link-local/metadata hosts.
      assertSafeWebhookUrl(e.url, cfg.allowInsecure ?? false)
    }
    this._endpoints = cfg.endpoints.map((e) => ({
      url: e.url,
      secret: e.secret,
      events: e.events ?? '*',
      signatureHeader: e.signatureHeader ?? 'X-Duck-Signature',
      id: e.id ?? e.url,
    }))
    // Bound maxAttempts so backoff `_backoffMs * 2^(attempt-1)` cannot overflow
    // setTimeout (max ~2^31 ms). 20 attempts at 500ms backoff = ~150 hours total
    // wall time worst case, which is well past any practical retry policy.
    this._maxAttempts = Math.min(Math.max(1, cfg.maxAttempts ?? 5), 20)
    this._backoffMs = cfg.backoffMs ?? 500
    this._timeoutMs = cfg.timeoutMs ?? 5_000
    this._fetch = cfg.fetch ?? globalThis.fetch
    this._deadLetter = cfg.deadLetter
  }

  /**
   * Attach to every relevant event on the bus. Returns a cleanup that
   * detaches every listener.
   */
  attach(bus: AuthEvents.IBus): () => void {
    // Collect the union of subscribed event names across all endpoints.
    const allNames = new Set<AuthEvents.EventName>()
    for (const e of this._endpoints) {
      if (e.events === '*') {
        for (const n of EVERY_EVENT) allNames.add(n)
      } else {
        for (const n of e.events) allNames.add(n)
      }
    }
    const subs: AuthEvents.Unsubscribe[] = []
    for (const name of allNames) {
      subs.push(
        bus.on(name, async (payload) => {
          await this.deliverOne(name, payload)
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
   */
  async deliverOne(name: AuthEvents.EventName, payload: unknown): Promise<void> {
    const eligible = this._endpoints.filter((e) => e.events === '*' || e.events.includes(name))
    await Promise.all(eligible.map((e) => this._deliverWithRetry(name, payload, e)))
  }

  private async _deliverWithRetry(
    name: AuthEvents.EventName,
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
    name: AuthEvents.EventName,
    payload: unknown,
    endpoint: { url: string; secret: string; signatureHeader: string },
  ): Promise<boolean> {
    const timestamp = Date.now()
    const body = JSON.stringify({ event: name, payload, timestamp })
    // Refuse oversize payloads at dispatch so a runaway event source can't
    // POST multi-MB bodies to every endpoint (would multiply outbound load).
    if (body.length > 1_048_576) {
      console.error(`[@gentleduck/auth] webhook payload for "${name}" exceeds 1 MiB cap; dropping`)
      return false
    }
    // HMAC covers the body + timestamp so verifiers can reject replays
    // outside a freshness window without trusting the body claim.
    const signature = authSignWebhookBody(endpoint.secret, body, timestamp)
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this._timeoutMs)
    try {
      // `redirect: 'error'` so the SSRF check at construction holds; otherwise
      // a remote can 30x-redirect to an internal IP we never approved.
      const res = await this._fetch(endpoint.url, {
        method: 'POST',
        body,
        headers: {
          'content-type': 'application/json',
          [endpoint.signatureHeader]: signature,
          'x-duck-timestamp': String(timestamp),
          'user-agent': '@gentleduck/auth-webhook',
        },
        signal: controller.signal,
        redirect: 'error',
      })
      return res.ok
    } finally {
      clearTimeout(timer)
    }
  }
}

/** Refuse loopback / private / link-local / cloud-metadata hosts. */
function assertSafeWebhookUrl(rawUrl: string, allowInsecure: boolean): void {
  let parsed: URL
  try {
    parsed = new URL(rawUrl)
  } catch {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', { detail: `webhook url is not a valid URL: ${rawUrl}` })
  }
  if (parsed.protocol !== 'https:' && !(allowInsecure && parsed.protocol === 'http:')) {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail: `webhook url must use HTTPS (${parsed.protocol}). Pass allowInsecure: true for dev only.`,
    })
  }
  const host = parsed.hostname.toLowerCase()
  // Block IPv4/IPv6 loopback + link-local + private + cloud-metadata.
  // Conservative regex-only guard; over-blocks `::ffff:` / `64:ff9b:` /
  // `2002:` literals since no legitimate webhook needs them.
  const danger = [
    /^localhost$/,
    /^127\./,
    /^0\./,
    /^10\./,
    /^192\.168\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^169\.254\./, // link-local + AWS/GCP metadata 169.254.169.254
    /^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./, // CGNAT 100.64/10
    /^0x/i, // hex IPv4 like 0x7f.0.0.1 (URL parser does NOT canonicalize)
    /^::1$/,
    /^\[?::\]?$/, // all-zeros IPv6 unspecified (often routes to local) - URL().hostname returns `[::]` with brackets
    /^\[?0:0:0:0:0:0:0:0\]?$/, // expanded all-zeros form
    /^\[?0:0:0:0:0:0:0:1\]?$/, // expanded loopback form
    /^fe80:/i,
    /^fc[0-9a-f]{2}:/i,
    /^fd[0-9a-f]{2}:/i,
    /^\[?::1\]?$/,
    /^\[?fe80::/i,
    // IPv4-mapped IPv6 `::ffff:...` routes to embedded v4; over-block.
    /^\[?::ffff:/i,
    /^\[?0:0:0:0:0:ffff:/i, // fully-expanded form
    // NAT64 well-known prefix `64:ff9b::/96` carries an inner IPv4
    // in the last 32 bits. Used to translate IPv6-only clients to IPv4
    // servers - operator misuse could route to loopback via this prefix.
    /^\[?64:ff9b:/i,
    /^\[?0064:ff9b:/i, // non-canonical leading-zero form
    // 6to4 prefix `2002::/16` carries an inner IPv4 in the next
    // 32 bits. Linux ships 6to4 by default - `2002:7f00:1::` routes to
    // 127.0.0.1. Over-block all 2002:: literals.
    /^\[?2002:/i,
  ]
  for (const pat of danger) {
    if (pat.test(host)) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: `webhook url host ${host} is private / loopback / link-local - refused (SSRF guard)`,
      })
    }
  }
}

/**
 * Sign a webhook body for transport. Caller-side consumers verify via
 * `authVerifyWebhookSignature`. Algorithm: `sha256=` + lowercase hex
 * digest, matching the convention most webhook tooling uses. When
 * `timestamp` is supplied, the HMAC covers `${timestamp}.${body}` -
 * pair it with the `X-Duck-Timestamp` header so verifiers can reject
 * replays outside a freshness window.
 *
 * Two-arg form (no timestamp) is retained for backwards compatibility
 * with consumers that already verify body-only signatures.
 */
export function authSignWebhookBody(secret: string, body: string, timestamp?: number): string {
  const payload = timestamp === undefined ? body : `${timestamp}.${body}`
  return `authSha256=${createHmac('sha256', secret).update(payload).digest('hex')}`
}

/**
 * Constant-time verify a webhook signature against the raw body. Apps
 * call this in their handler before parsing the JSON. When the
 * `X-Duck-Timestamp` header was supplied, pass `timestamp` + tolerance
 * to defend against replays. Default tolerance: 5 minutes.
 */
export function authVerifyWebhookSignature(
  secret: string,
  body: string,
  signature: string,
  opts: { timestamp?: number; toleranceMs?: number } = {},
): boolean {
  if (opts.timestamp !== undefined) {
    // NaN timestamp would silently bypass `Math.abs(...) > tolerance`.
    if (typeof opts.timestamp !== 'number' || !Number.isFinite(opts.timestamp)) return false
    const tolerance = opts.toleranceMs ?? 5 * 60_000
    if (Math.abs(Date.now() - opts.timestamp) > tolerance) return false
  }
  const expected = authSignWebhookBody(secret, body, opts.timestamp)
  const a = Buffer.from(signature)
  const b = Buffer.from(expected)
  return a.length === b.length && timingSafeEqual(a, b)
}

/** Every event name in the AuthEvents.EventMap; used to materialize `'*'` subscriptions. */
const EVERY_EVENT: AuthEvents.EventName[] = [
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

export namespace AuthWebhookDeliverer {
  export interface IConfig {
    endpoints: AuthWebhookDeliverer.IEndpoint[]
    /** Maximum delivery attempts before dead-lettering. Default 5. */
    maxAttempts?: number
    /** Base backoff in ms (exponential). Default 500ms (so 0.5s, 1s, 2s, 4s, 8s). */
    backoffMs?: number
    /** Request timeout per delivery, ms. Default 5_000. */
    timeoutMs?: number
    /** Override fetch impl (tests). */
    fetch?: typeof globalThis.fetch
    /** Sink for permanently-failed deliveries. */
    deadLetter?: AuthWebhookDeliverer.IDeadLetterSink
    /**
     * Accept non-HTTPS endpoint URLs. Default false. Dev-only - leaves
     * webhook payloads readable on the wire. The SSRF guard still
     * blocks loopback / private / link-local / cloud-metadata hosts
     * regardless of this flag.
     */
    allowInsecure?: boolean
  }

  export interface IEndpoint {
    /** Absolute HTTPS URL. */
    url: string
    /** Shared secret; signs the HMAC header. Treat as confidential. */
    secret: string
    /** Event names this endpoint receives. Default `'*'` -> every event. */
    events?: AuthEvents.EventName[] | '*'
    /** Header name carrying the HMAC. Default `'X-Duck-Signature'`. */
    signatureHeader?: string
    /**
     * Caller-supplied identifier for the endpoint (UI labels, audit
     * logs). Default `url`.
     */
    id?: string
  }

  export interface IDeadLetterSink {
    put(envelope: AuthWebhookDeliverer.IDeadLetterEntry): Promise<void>
  }

  export interface IDeadLetterEntry {
    endpointId: string
    endpointUrl: string
    eventName: AuthEvents.EventName
    payload: unknown
    attempts: number
    lastError: string
    firstAttemptAt: number
    lastAttemptAt: number
  }
}
