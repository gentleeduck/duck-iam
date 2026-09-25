/** Webhook delivery for the Events bus: forwards each emission to N consumer URLs over HTTPS with an
 *  HMAC signature, exponential-backoff retry and a dead-letter sink. The endpoint set is supplied up
 *  front; a self-service webhook UI is the host's to wire, reloading the subscriber on change. */

import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto'
import { AuthError, redactSecrets } from '../errors'
import type { Events } from '../events'
import { EVERY_EVENT } from '../events'
import { assertResolvedHostIsPublic, assertSafeOutboundUrl } from '../url-validators'
import {
  BACKOFF_BASE_MAX_MS,
  BACKOFF_DEFAULT_MS,
  BACKOFF_MAX_MS,
  backoffFor,
  HEADER_TOKEN,
  jitterSource,
  MAX_ATTEMPTS,
  PAYLOAD_MAX_BYTES,
  sanitiseEndpointUrl,
  TIMEOUT_DEFAULT_MS,
  TOLERANCE_DEFAULT_MS,
} from './webhooks.constants'

/** Subscribes the bus, signs and POSTs each emit to the configured endpoints, retries with exponential
 *  backoff, and dead-letters on permanent failure. */
const BYTES = new TextEncoder()

/** Whether repeating the request could ever change the answer. 4xx says the request itself is wrong
 *  and it is byte-identical every attempt, except the two that mean "later": 408 and 429. */
function isPermanentStatus(status: number): boolean {
  if (status === 408 || status === 429) return false
  return status >= 400 && status < 500
}

export class WebhookDeliverer {
  private readonly _endpoints: Array<
    Required<Omit<WebhookDeliverer.IEndpoint, 'events' | 'signatureHeader' | 'id'>> & {
      events: Events.EventName[] | '*'
      signatureHeader: string
      id: string
    }
  >
  private readonly _maxAttempts: number
  private readonly _backoffMs: number
  private readonly _timeoutMs: number
  private readonly _fetch: typeof globalThis.fetch
  private readonly _deadLetter: WebhookDeliverer.IDeadLetterSink | undefined
  private readonly _resolveHost: ((hostname: string) => Promise<string[]>) | undefined
  private readonly _redact: (payload: unknown) => unknown
  private readonly _random: () => number
  private readonly _attached = new WeakMap<Events.IBus, () => void>()
  private readonly _inflight = new Set<Promise<unknown>>()

  constructor(cfg: WebhookDeliverer.Cfg) {
    if (!cfg.endpoints?.length) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthWebhookDeliverer requires at least one endpoint',
      })
    }
    for (const e of cfg.endpoints) {
      if (!e.url || !e.secret) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: 'AuthWebhookDeliverer endpoint requires both url + secret',
        })
      }
      // The SSRF guard: non-HTTPS, loopback, private, link-local and metadata hosts are refused.
      assertSafeOutboundUrl(e.url, { allowInsecure: cfg.allowInsecure ?? false, label: 'webhook url' })
      // The name reaches `fetch` as a header key, so a typo carrying a space or a colon throws on
      // every request for every event, forever. Refused once here instead.
      if (e.signatureHeader !== undefined && !HEADER_TOKEN.test(e.signatureHeader)) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: `AuthWebhookDeliverer signatureHeader must be a valid header name (got ${JSON.stringify(e.signatureHeader)})`,
        })
      }
    }
    this._endpoints = cfg.endpoints.map((e) => ({
      url: e.url,
      secret: e.secret,
      events: e.events ?? '*',
      signatureHeader: e.signatureHeader ?? 'X-Duck-Signature',
      // The default identifier is read by an operator and stored with every failure, so it gets the
      // part of the URL that names the endpoint and not the query string that may authorise it.
      id: e.id ?? sanitiseEndpointUrl(e.url),
    }))
    // The ladder is `while (attempt < this._maxAttempts)`, and every comparison against NaN is false, so
    // a non-finite value does not raise the ceiling - it removes the ladder. Nothing was ever sent, and
    // the event was dead-lettered with `attempts: 0` and an empty `lastError` to say so.
    const maxAttempts = cfg.maxAttempts ?? 5
    if (!Number.isFinite(maxAttempts)) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `AuthWebhookDeliverer maxAttempts must be a finite number (got ${maxAttempts})`,
      })
    }
    this._maxAttempts = Math.min(Math.max(1, maxAttempts), MAX_ATTEMPTS)
    // A negative base makes every wait negative, which `setTimeout` floors to zero, so the ladder
    // that exists to spare a struggling consumer hammers it instead.
    const backoff = cfg.backoffMs ?? BACKOFF_DEFAULT_MS
    if (!Number.isFinite(backoff) || backoff < 0 || backoff > BACKOFF_BASE_MAX_MS) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `AuthWebhookDeliverer backoffMs must be a finite number between 0 and ${BACKOFF_BASE_MAX_MS}`,
      })
    }
    this._backoffMs = backoff
    // `setTimeout` floors a negative or non-finite delay to zero and overflows anything past 2^31-1 to
    // zero too, so an unusable timeout aborts each request before it leaves and spends the whole ladder
    // failing on nothing.
    const timeoutMs = cfg.timeoutMs ?? TIMEOUT_DEFAULT_MS
    if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > BACKOFF_MAX_MS) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `AuthWebhookDeliverer timeoutMs must be a finite number between 1 and ${BACKOFF_MAX_MS}`,
      })
    }
    this._timeoutMs = timeoutMs
    this._fetch = cfg.fetch ?? globalThis.fetch
    this._deadLetter = cfg.deadLetter
    this._resolveHost = cfg.resolveHost
    this._redact = cfg.redact ?? redactSecrets
    this._random = cfg.random ?? jitterSource
  }

  /** Attach to every relevant event on the bus, answering with a cleanup that detaches them. Attaching
   *  the same bus twice is the same subscription, so a reload that skips the cleanup cannot double
   *  the load on every consumer. */
  attach(bus: Events.IBus): () => void {
    const existing = this._attached.get(bus)
    if (existing) return existing

    const allNames = new Set<Events.EventName>()
    for (const e of this._endpoints) {
      if (e.events === '*') {
        for (const n of EVERY_EVENT) allNames.add(n)
      } else {
        for (const n of e.events) allNames.add(n)
      }
    }
    const subs: Events.Unsubscribe[] = []
    for (const name of allNames) {
      subs.push(
        bus.on(name, (payload) => {
          // Not awaited: `emit` awaits each handler in turn, so awaiting the retry ladder here puts
          // every backoff and every request timeout on the clock of the sign-in that emitted the
          // event. A dead consumer would add half a minute to an authentication.
          this._track(this.deliverOne(name, payload))
        }),
      )
    }
    const off = () => {
      this._attached.delete(bus)
      for (const unsubscribe of subs) unsubscribe()
    }
    this._attached.set(bus, off)
    return off
  }

  /** Settle every delivery still in flight. For a graceful shutdown, and for tests. */
  async drain(): Promise<void> {
    while (this._inflight.size > 0) await Promise.allSettled([...this._inflight])
  }

  private _track(work: Promise<unknown>): void {
    const tracked = work.catch((err) => {
      console.error('[@gentleduck/auth] webhook delivery failed outside the retry loop', err)
    })
    this._inflight.add(tracked)
    void tracked.finally(() => this._inflight.delete(tracked))
  }

  /** The per-endpoint fanout and retry loop for one (name, payload) pair, public for tests and manual
   *  re-deliveries. One outcome per eligible endpoint, so an operator can see whether it landed; an
   *  empty array means nothing subscribes to this event. */
  async deliverOne(name: Events.EventName, payload: unknown): Promise<WebhookDeliverer.Delivery[]> {
    const eligible = this._endpoints.filter((e) => e.events === '*' || e.events.includes(name))
    return Promise.all(eligible.map((e) => this._deliverWithRetry(name, payload, e)))
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
  ): Promise<WebhookDeliverer.Delivery> {
    const firstAttemptAt = Date.now()
    const deliveryId = randomUUID()
    let lastError = ''
    let attempt = 0

    // Serialised once, before the first attempt. Inside the loop a circular payload or a bigint
    // read as a failed transport attempt, so nothing was ever sent and the caller still waited
    // through every backoff for an answer that could not change.
    let body: string
    try {
      body = JSON.stringify({
        deliveryId,
        event: name,
        payload: this._redact(payload),
        timestamp: firstAttemptAt,
      })
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err)
      await this._deadLetterPut(endpoint, name, payload, { attempts: 0, firstAttemptAt, lastError })
      return { attempts: 0, delivered: false, endpointId: endpoint.id, lastError }
    }
    // The construction-time guard sees the spelling of the host and nothing else, so a name that
    // resolves inward passes it. Checked once, before the ladder: a name pointing inward will point
    // inward again in eight seconds, so retrying it only delays the same refusal.
    try {
      await this._assertEndpointResolvesOutward(endpoint.url)
    } catch (err) {
      lastError = err instanceof AuthError ? String(err.meta.detail ?? err.code) : String(err)
      await this._deadLetterPut(endpoint, name, payload, { attempts: 0, firstAttemptAt, lastError })
      return { attempts: 0, delivered: false, endpointId: endpoint.id, lastError }
    }
    if (BYTES.encode(body).length > PAYLOAD_MAX_BYTES) {
      console.error(`[@gentleduck/auth] webhook payload for "${name}" exceeds the ${PAYLOAD_MAX_BYTES} byte cap`)
      lastError = `payload exceeds ${PAYLOAD_MAX_BYTES} byte cap`
      await this._deadLetterPut(endpoint, name, payload, { attempts: 0, firstAttemptAt, lastError })
      return { attempts: 0, delivered: false, endpointId: endpoint.id, lastError }
    }

    while (attempt < this._maxAttempts) {
      attempt++
      try {
        const outcome = await this._dispatch(body, Date.now(), deliveryId, endpoint)
        if (outcome.state === 'delivered') return { attempts: attempt, delivered: true, endpointId: endpoint.id }
        lastError = outcome.reason
        // A rejected body, a gone endpoint or a payload over the cap answer the same way however
        // many times they are asked, so the remaining attempts buy nothing but delay before the
        // dead letter that was always coming.
        if (outcome.state === 'permanent') break
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err)
      }
      if (attempt < this._maxAttempts) {
        await new Promise((r) => setTimeout(r, backoffFor(this._backoffMs, attempt, this._random)))
      }
    }
    await this._deadLetterPut(endpoint, name, payload, { attempts: attempt, firstAttemptAt, lastError })
    return { attempts: attempt, delivered: false, endpointId: endpoint.id, lastError }
  }

  private async _assertEndpointResolvesOutward(url: string): Promise<void> {
    if (!this._resolveHost) return
    for (const address of await this._resolveHost(new URL(url).hostname)) {
      assertResolvedHostIsPublic(address, 'webhook url')
    }
  }

  private async _deadLetterPut(
    endpoint: { url: string; id: string },
    eventName: Events.EventName,
    payload: unknown,
    meta: { attempts: number; firstAttemptAt: number; lastError: string },
  ): Promise<void> {
    if (!this._deadLetter) return
    await this._deadLetter
      .put({
        attempts: meta.attempts,
        endpointId: endpoint.id,
        endpointUrl: sanitiseEndpointUrl(endpoint.url),
        eventName,
        firstAttemptAt: meta.firstAttemptAt,
        lastAttemptAt: Date.now(),
        lastError: meta.lastError,
        payload: this._redact(payload),
      })
      .catch(() => {
        // A failing dead-letter sink is not fatal: log and drop.
      })
  }

  private async _dispatch(
    body: string,
    sentAt: number,
    deliveryId: string,
    endpoint: { url: string; secret: string; signatureHeader: string },
  ): Promise<{ state: 'delivered' } | { state: 'retry' | 'permanent'; reason: string }> {
    // SECURITY: `sentAt` is per attempt, not per delivery. `verifyWebhookSignature` refuses a stamp
    // older than its tolerance, so a retry carrying the first attempt's stamp read as too old and the
    // consumer answered `false` - the same answer as a wrong secret. The body's own `timestamp` stays
    // the event time, so attempts stay byte-identical and `deliveryId` still keys idempotency; the HMAC
    // covers both, so neither substitutes for the other.
    const signature = signWebhookBody(endpoint.secret, body, sentAt)
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this._timeoutMs)
    try {
      // `redirect: 'error'`, so the construction-time SSRF check holds: a remote could otherwise
      // 30x-redirect to an internal IP nothing approved.
      const res = await this._fetch(endpoint.url, {
        body,
        headers: {
          'content-type': 'application/json',
          [endpoint.signatureHeader]: signature,
          'user-agent': '@gentleduck/auth-webhook',
          'x-duck-delivery-id': deliveryId,
          'x-duck-timestamp': String(sentAt),
        },
        method: 'POST',
        redirect: 'error',
        signal: controller.signal,
      })
      if (res.ok) return { state: 'delivered' }
      return {
        reason: `non-2xx response (${res.status})`,
        state: isPermanentStatus(res.status) ? 'permanent' : 'retry',
      }
    } finally {
      clearTimeout(timer)
    }
  }
}

/**
 * Consumers verify with `verifyWebhookSignature`. The format is `authSha256=` plus a lowercase hex
 * digest, deliberately not GitHub's and Stripe's `sha256=`, which carries a different payload under the
 * same name, though the verifier accepts either spelling.
 */
export function signWebhookBody(secret: string, body: string, timestamp?: number): string {
  assertSecret(secret)
  const payload = timestamp === undefined ? body : `${timestamp}.${body}`
  return `${SIGNATURE_PREFIX}${createHmac('sha256', secret).update(payload).digest('hex')}`
}

/**
 * Constant-time verify a webhook signature against the raw body, before the handler parses the JSON.
 * `timestamp` must be the `X-Duck-Timestamp` value the signature covers; a stale one is refused.
 * Default tolerance 5 minutes.
 *
 * WARN: that bounds a replay to the window rather than preventing one inside it. A handler that must
 * act once per delivery keys an idempotency store on `X-Duck-Delivery-Id`.
 */
export function verifyWebhookSignature(
  secret: string,
  body: string,
  signature: string,
  opts: { timestamp?: number; toleranceMs?: number } = {},
): boolean {
  assertSecret(secret)
  const tolerance = opts.toleranceMs ?? TOLERANCE_DEFAULT_MS
  // A negative window refuses every signature including a fresh one, so the sign error in a
  // consumer's config would present as every delivery being rejected for a bad secret.
  if (!Number.isFinite(tolerance) || tolerance < 0) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'verifyWebhookSignature toleranceMs must be a non-negative finite number',
    })
  }
  if (opts.timestamp !== undefined) {
    // NaN timestamp would silently bypass `Math.abs(...) > tolerance`.
    if (typeof opts.timestamp !== 'number' || !Number.isFinite(opts.timestamp)) return false
    if (Math.abs(Date.now() - opts.timestamp) > tolerance) return false
  }
  const prefix = ACCEPTED_PREFIXES.find((p) => signature.startsWith(p))
  if (prefix === undefined) return false
  const supplied = Buffer.from(signature.slice(prefix.length))
  const expected = Buffer.from(signWebhookBody(secret, body, opts.timestamp).slice(SIGNATURE_PREFIX.length))
  return supplied.length === expected.length && timingSafeEqual(supplied, expected)
}

const SIGNATURE_PREFIX = 'authSha256='
const ACCEPTED_PREFIXES = [SIGNATURE_PREFIX, 'sha256=']

/**
 * An empty secret produces a signature anyone can compute, and the helpers are what a consumer
 * calls: construction refuses one on an endpoint, so refusing it here too closes the other half.
 */
function assertSecret(secret: string): void {
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new AuthError('AUTH_MISCONFIGURED', { detail: 'webhook signing requires a non-empty secret' })
  }
}

/** Per-endpoint delivery results and the retry state behind them. */
export namespace WebhookDeliverer {
  /** What one endpoint made of one event. Returned by `deliverOne`. */
  export interface Delivery {
    endpointId: string
    /** True when an attempt got a 2xx; false when every attempt was spent. */
    delivered: boolean
    /** Attempts actually made, including the successful one. */
    attempts: number
    /** Why the last attempt failed. Absent on a delivered event. */
    lastError?: string
  }

  export interface Cfg {
    endpoints: WebhookDeliverer.IEndpoint[]
    /** Maximum delivery attempts before dead-lettering. Default 5. */
    maxAttempts?: number
    /** Base backoff in ms (exponential). Default 500ms (so 0.5s, 1s, 2s, 4s, 8s). */
    backoffMs?: number
    /** Request timeout per delivery, ms. Default 5_000. */
    timeoutMs?: number
    /** For tests. */
    fetch?: typeof globalThis.fetch
    /** Where a permanently failed delivery goes. */
    deadLetter?: WebhookDeliverer.IDeadLetterSink
    /** Accept non-HTTPS endpoint URLs, leaving payloads readable on the wire. Dev-only, default false.
     *  The SSRF guard still blocks loopback, private, link-local and cloud-metadata hosts regardless. */
    allowInsecure?: boolean
    /** Resolves an endpoint hostname to its addresses, checked against the same ranges before each
     *  request. Without it the guard sees only the host's spelling, so a name pointing at 127.0.0.1 is
     *  accepted; `dns.promises.lookup(hostname, { all: true })` is the Node wiring.
     *  WARN: this closes the name, not the race, since `fetch` resolves again when it connects. */
    resolveHost?: (hostname: string) => Promise<string[]>
    /** Redacts a payload before it is signed, sent and dead-lettered. Blanks every secret-bearing key at
     *  any depth by default: a `session.created` payload carries the session row and the identity, and
     *  both would otherwise reach a third party verbatim. */
    redact?: (payload: unknown) => unknown
    /** Jitter source for the retry backoff. Tests pin it; nothing else should pass it. */
    random?: () => number
  }

  export interface IEndpoint {
    /** Absolute HTTPS URL. */
    url: string
    /** Signs the HMAC header; confidential. */
    secret: string
    /** Event names this endpoint receives. Default `'*'` -> every event. */
    events?: Events.EventName[] | '*'
    /** Header name carrying the HMAC. Default `'X-Duck-Signature'`. */
    signatureHeader?: string
    /** For UI labels and audit logs. Defaults to `url`. */
    id?: string
  }

  export interface IDeadLetterSink {
    put(envelope: WebhookDeliverer.IDeadLetterEntry): Promise<void>
  }

  export interface IDeadLetterEntry {
    endpointId: string
    endpointUrl: string
    eventName: Events.EventName
    payload: unknown
    attempts: number
    lastError: string
    firstAttemptAt: number
    lastAttemptAt: number
  }
}

export function webhookDeliverer(cfg: WebhookDeliverer.Cfg): WebhookDeliverer {
  return new WebhookDeliverer(cfg)
}
