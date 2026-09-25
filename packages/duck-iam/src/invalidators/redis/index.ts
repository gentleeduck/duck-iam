import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import type { IamEngineTypes } from '../../core/engine/engine.types'

/** Redis invalidator integration types. Type-only namespace - zero bundle cost. */
export namespace IamRedisInvalidator {
  /**
   * Minimal pub/sub surface; ioredis and node-redis v4+ both fit, so neither is a hard dependency.
   * INFO: back it with two connections - Redis allows no other commands on a subscribed connection.
   */
  export interface IPubSubLike {
    /** Publishes `message` on `channel`. A returned promise's rejection goes to `onPublishError`. */
    publish(channel: string, message: string): unknown
    /** Subscribes `handler` to raw messages on `channel`. A throw or rejection goes to `onSubscribeError`. */
    subscribe(channel: string, handler: (message: string) => void): void | Promise<void>
    /** Detaches from `channel` once the last handler leaves (e.g. on engine `dispose()`). Optional. */
    unsubscribe?(channel: string): void | Promise<void>
  }

  /** Configures {@link createIamRedisInvalidator}. */
  export interface IConfig {
    /** Redis pub/sub adapter implementing {@link IPubSubLike}. */
    client: IPubSubLike
    /**
     * Channel name; engines on the same channel share invalidations. Defaults to `'duck-iam:invalidate'`.
     * Prefer {@link tenantId} to building per-tenant names by hand.
     */
    channel?: string
    /**
     * Scopes the channel to `<channel>:tenant:<tenantId>`; must match `/^[A-Za-z0-9_-]{1,64}$/`.
     * SECURITY: set `secret` too - routing alone does not stop a relayed envelope; the signed channel binding does.
     *
     * @example
     * ```ts
     * createIamRedisInvalidator({ client, secret, tenantId: req.tenantSlug })
     * ```
     */
    tenantId?: string
    /**
     * Shared HMAC-SHA256 secret; inbound envelopes that do not verify are dropped.
     * SECURITY: unset (the default), anyone with PUBLISH rights on the channel can wipe caches. Set it in production.
     */
    secret?: string | null
    /**
     * Called when `client.publish` throws or rejects. Local caches are already cleared, but peers miss the event.
     * Without it, a coalesced warning is logged.
     */
    onPublishError?: (err: Error, channel: string) => void
    /**
     * Called when `client.subscribe` fails; `healthCheck()` then reports `subscribed: false` until a retry succeeds.
     * WARN: retries ride on `publish` (at most every 5s), so a node that never writes never recovers.
     */
    onSubscribeError?: (err: Error, channel: string) => void
    /**
     * Replaces the drop warning, coalesced per channel per 60s; `suppressed` counts drops since the last call.
     * Also receives publish failures when `onPublishError` is unset. A throwing hook is ignored.
     * SECURITY: `reason` never carries inbound message content, and coalescing stops inbound traffic flooding the hook.
     */
    onMessageDropped?: (reason: string, channel: string, suppressed: number) => void
    /**
     * Accepts pre-v2 envelopes, whose signature does not cover the channel, during a rolling upgrade.
     * SECURITY: while on, an envelope signed for any channel sharing this secret verifies here; warns at construction.
     */
    acceptLegacyUnboundEnvelopes?: boolean
  }
}

const DEFAULT_CHANNEL = 'duck-iam:invalidate'

/** Whether `value` has a callable `then`, i.e. can still reject later; client return types vary. */
function isThenable(value: unknown): value is PromiseLike<unknown> {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) return false
  return typeof Reflect.get(value, 'then') === 'function'
}

/** Replay window in ms. Signed envelopes whose `ts` is further than this from now, either way, are dropped. */
const REPLAY_WINDOW_MS = 30_000

/** Cap on remembered signatures, so a flood costs bounded memory rather than unbounded. */
const MAX_SEEN_SIGNATURES = 5_000

/** Signatures already applied on this channel, so a verbatim envelope is not replayed inside the window. */
interface ISeenEnvelopes {
  /** `false` when this signature was already accepted; recording it otherwise. */
  accept(sig: string, now: number): boolean
}

/** Entries are inserted in time order, so pruning stops at the first one still inside the window. */
function createSeenEnvelopes(): ISeenEnvelopes {
  const seen = new Map<string, number>()
  return {
    accept(sig, now) {
      for (const [seenSig, at] of seen) {
        if (now - at <= REPLAY_WINDOW_MS) break
        seen.delete(seenSig)
      }
      if (seen.has(sig)) return false
      seen.set(sig, now)
      // Oldest first, matching insertion order; the window prune above usually gets there first.
      while (seen.size > MAX_SEEN_SIGNATURES) {
        const oldest = seen.keys().next()
        if (oldest.done) break
        seen.delete(oldest.value)
      }
      return true
    },
  }
}

/**
 * Wire-format version. Bump when the envelope shape changes incompatibly.
 * SECURITY: v2 signs the channel, so an envelope signed for one channel does not verify on another sharing the secret.
 */
const ENVELOPE_V = 2

/** The pre-v2 wire version, accepted only under `acceptLegacyUnboundEnvelopes`. */
const ENVELOPE_V_UNBOUND = 1

/** Channels already reported as accepting pre-v2, channel-unbound envelopes. */
const _UNBOUND_WARNED = new Set<string>()

/**
 * Channels already warned about running unsigned.
 * NOTE: keyed per channel so each tenant's invalidator warns once; a process-wide latch would hide all but the first.
 */
const _UNSIGNED_WARNED = new Set<string>()

/** Drop-warn coalescing state per key: time of the last warn and drops suppressed since. */
const _DROP_WARN_STATE = new Map<string, { lastWarn: number; suppressed: number }>()
/** Minimum gap between drop warns for a single channel. */
const DROP_WARN_WINDOW_MS = 60_000
/**
 * Minimum gap between `subscribe` retries after a failure.
 * NOTE: retries ride on `publish`, so without a floor an outage during a write burst issues one subscribe per write.
 */
const RESUBSCRIBE_MIN_INTERVAL_MS = 5_000

/**
 * Log-safe channel name: the tenant segment becomes a truncated, unsalted SHA-256, so it still matches across hosts.
 * SECURITY: drop warnings are attacker-triggerable, so logs must not name tenants. Not a confidentiality boundary.
 */
function redactChannel(channelName: string): string {
  const marker = ':tenant:'
  const at = channelName.lastIndexOf(marker)
  if (at === -1) return channelName
  const tenantId = channelName.slice(at + marker.length)
  const digest = createHash('sha256').update(tenantId).digest('hex').slice(0, 8)
  return `${channelName.slice(0, at)}${marker}${digest}`
}

/** SECURITY: pre-auth limits on inbound messages, checked before the HMAC, so keep them cheap and stack-safe. */
const MAX_WIRE_BYTES = 16 * 1024
const MAX_PAYLOAD_DEPTH = 8
const MAX_PAYLOAD_KEYS = 64
/** Recursion cap on {@link canonicalJSON} itself, for callers without the wire guard in front. */
const CANONICAL_MAX_DEPTH = 16

/**
 * Nesting depth and total key count of a parsed JSON value, or `null` once either cap is exceeded.
 * SECURITY: iterative, so hostile nesting cannot overflow the stack.
 */
function _measurePayload(root: unknown): { depth: number; keys: number } | null {
  if (root === null || typeof root !== 'object') return { depth: 0, keys: 0 }
  // Stack entries: [node, depth]. Depth of root container itself is 1.
  const stack: Array<[unknown, number]> = [[root, 1]]
  let maxDepth = 0
  let totalKeys = 0
  while (stack.length > 0) {
    const top = stack.pop()
    if (!top) break
    const [node, depth] = top
    if (depth > maxDepth) maxDepth = depth
    if (depth > MAX_PAYLOAD_DEPTH) return null
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        const child = node[i]
        if (child !== null && typeof child === 'object') stack.push([child, depth + 1])
      }
    } else if (node !== null && typeof node === 'object') {
      const keys = Object.keys(node)
      totalKeys += keys.length
      if (totalKeys > MAX_PAYLOAD_KEYS) return null
      for (const key of keys) {
        const child: unknown = Reflect.get(node, key)
        if (child !== null && typeof child === 'object') stack.push([child, depth + 1])
      }
    }
  }
  return { depth: maxDepth, keys: totalKeys }
}

/**
 * JSON with sorted object keys, so publisher and verifier hash the same bytes whatever the key order.
 * Depth-capped for the publish path, which has no wire guard in front of it.
 */
function canonicalJSON(v: unknown, _depth = 0): string {
  if (_depth > CANONICAL_MAX_DEPTH) throw new Error('canonicalJSON: max depth exceeded')
  if (v === null || typeof v !== 'object') return JSON.stringify(v)
  if (Array.isArray(v)) return `[${v.map((x) => canonicalJSON(x, _depth + 1)).join(',')}]`
  const keys = Object.keys(v).sort()
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJSON(Reflect.get(v, k), _depth + 1)}`).join(',')}}`
}

/**
 * HMAC pre-image for publishing: canonical JSON of the value after a JSON round-trip, which is what the receiver sees.
 * NOTE: without the round-trip, JSON-lossy values such as `roleId: undefined` hash differently and never verify.
 */
function signingPreimage(value: unknown): string {
  return canonicalJSON(JSON.parse(JSON.stringify(value)))
}

/** Signed wire envelope `{ v, sig, payload }`; unsigned mode sends `{ instanceId, event }` instead. */
interface SignedEnvelope<TRole extends string> {
  readonly v: 2
  readonly sig: string
  readonly payload: {
    readonly channel: string
    readonly instanceId: string
    readonly event: IamEngineTypes.IInvalidateEvent<TRole>
    readonly ts: number
  }
}

/**
 * Compares two hex strings; `false` on any type, length or decode mismatch.
 * SECURITY: constant-time via `timingSafeEqual`, never `===`. Lengths go first because it throws on a mismatch.
 */
function safeHexEqual(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  if (a.length !== b.length) return false
  let ab: Buffer
  let bb: Buffer
  try {
    ab = Buffer.from(a, 'hex')
    bb = Buffer.from(b, 'hex')
  } catch {
    return false
  }
  // SECURITY: `ab.length === 0` is unreachable today (the caller's `b` is a full HMAC) but stops two empty
  // buffers comparing equal.
  if (ab.length !== bb.length || ab.length === 0) return false
  return timingSafeEqual(ab, bb)
}

/**
 * Cross-instance cache invalidation over Redis pub/sub. Delivery is at-least-once; invalidation is idempotent.
 * SECURITY: set `secret` in production; signed envelopes are held to a 30s replay window and applied at most once.
 *
 * @template TRole - Role identifier union the engine is parameterised over.
 * @param config - Supplies the client and optional channel; see {@link IamRedisInvalidator.IConfig}.
 * @returns An {@link IamEngineTypes.IInvalidator} bound to the configured channel.
 * @example
 * ```ts
 * import { createIamRedisInvalidator } from '@gentleduck/iam/invalidators/redis'
 *
 * const engine = new IamEngine({
 *   adapter,
 *   invalidator: createIamRedisInvalidator({
 *     client: redisPubSub,
 *     secret: process.env.IAM_INVALIDATE_SECRET,
 *   }),
 * })
 * ```
 */
export function createIamRedisInvalidator<TRole extends string = string>(
  config: IamRedisInvalidator.IConfig,
): IamEngineTypes.IInvalidator<TRole> {
  const baseChannel = config.channel ?? DEFAULT_CHANNEL
  // SECURITY: shape-check the tenant slug so it cannot inject pub/sub wildcards.
  let channel = baseChannel
  if (config.tenantId !== undefined) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(config.tenantId)) {
      throw new Error(
        '[@gentleduck/iam:invalidator:redis] tenantId must match /^[A-Za-z0-9_-]{1,64}$/ (got ' +
          JSON.stringify(config.tenantId) +
          ')',
      )
    }
    channel = `${baseChannel}:tenant:${config.tenantId}`
  }
  const instanceId = generateInstanceId()
  const handlers = new Set<(event: IamEngineTypes.IInvalidateEvent<TRole>) => void>()
  // SECURITY: refuse an empty key rather than sign with it. `createHmac('sha256', '')` is legal, so the documented
  // `secret: process.env.IAM_INVALIDATE_SECRET` wiring would run "signed" with a key anyone can guess whenever the
  // variable is set but empty - and the unsigned-channel warning would stay silent because a secret was present.
  if (config.secret !== undefined && config.secret !== null && config.secret.length === 0) {
    throw new Error(
      '[@gentleduck/iam:invalidator:redis] secret must not be empty; anyone can sign with an empty key. ' +
        'Omit it to run the channel unsigned, or pass a real key.',
    )
  }
  const secret = config.secret ?? null
  const acceptLegacyUnbound = config.acceptLegacyUnboundEnvelopes === true

  if (acceptLegacyUnbound && secret !== null && !_UNBOUND_WARNED.has(channel)) {
    _UNBOUND_WARNED.add(channel)
    console.warn(
      `[@gentleduck/iam:invalidator:redis] \`acceptLegacyUnboundEnvelopes\` is on for channel ${JSON.stringify(redactChannel(channel))} - pre-v2 envelopes are accepted, and their signature does not cover the channel. Any party holding this secret for any channel can forge messages here. Turn it off once every node publishes v:${ENVELOPE_V}.`,
    )
  }

  if (secret === null && !_UNSIGNED_WARNED.has(channel)) {
    _UNSIGNED_WARNED.add(channel)
    console.warn(
      `[@gentleduck/iam:invalidator:redis] \`secret\` not set on channel ${JSON.stringify(redactChannel(channel))} - accepting unsigned pub/sub. Anyone with PUBLISH rights on the channel can wipe caches. Pass \`secret\` to require HMAC-SHA256.`,
    )
  }

  /**
   * Reports an inbound drop or publish failure, at most once per kind and channel per window.
   * SECURITY: each kind has its own budget, so attacker-sent junk cannot coalesce away a publish-failure warning.
   */
  function reportDrop(kind: 'inbound' | 'publish', channelName: string, reason: string): void {
    const now = Date.now()
    // NUL-separated, so the two kinds never share a key.
    const key = `${kind}\u0000${channelName}`
    const state = _DROP_WARN_STATE.get(key)
    const emit = (suppressed: number, tail: string): void => {
      if (config.onMessageDropped) {
        try {
          config.onMessageDropped(reason, channelName, suppressed)
        } catch {
          /* operator hook itself threw - preserve fail-soft contract */
        }
        return
      }
      console.warn(
        `[@gentleduck/iam:invalidator:redis] dropping unverifiable message on channel ${JSON.stringify(redactChannel(channelName))} (${reason}). ${tail}`,
      )
    }
    if (!state) {
      _DROP_WARN_STATE.set(key, { lastWarn: now, suppressed: 0 })
      emit(0, `Further drops within ${DROP_WARN_WINDOW_MS}ms are coalesced.`)
      return
    }
    if (now - state.lastWarn < DROP_WARN_WINDOW_MS) {
      state.suppressed++
      return
    }
    // Window elapsed; surface the suppressed count so operators see sustained abuse.
    const suppressed = state.suppressed
    state.lastWarn = now
    state.suppressed = 0
    emit(suppressed, `${suppressed} prior drops coalesced.`)
  }

  /** Inbound-drop reporter handed to {@link parseIncoming}. */
  const warnDropOnce = (channelName: string, reason: string): void => reportDrop('inbound', channelName, reason)

  // Only signed envelopes carry a signature to remember; without a secret nothing here is authentic anyway.
  const seenEnvelopes = secret === null ? null : createSeenEnvelopes()

  function reportSubscribeFailure(err: unknown): void {
    const error = err instanceof Error ? err : new Error(String(err))
    try {
      config.onSubscribeError?.(error, channel)
    } catch {
      /* operator hook itself threw - preserve fail-soft contract */
    }
    if (!config.onSubscribeError) {
      console.warn(
        `[@gentleduck/iam:invalidator:redis] subscribe to ${JSON.stringify(redactChannel(channel))} failed (${error.message}) - this node receives no invalidations and serves stale allow decisions until a retry succeeds. A retry is attempted from publish() (at most once every ${RESUBSCRIBE_MIN_INTERVAL_MS}ms) and from any further subscribe(); an engine calls subscribe() once at setup and never again, so a node that never writes never retries. engine.healthCheck() reports \`invalidator: { subscribed: false }\` meanwhile. Pass \`onSubscribeError\` to handle this.`,
      )
    }
  }

  // NOTE: `subscribed` latches only once `subscribe()` resolves, so a failed attempt stays retryable.
  // A publish-driven (`opportunistic`) retry is floored and never initiates: a subscribed client cannot publish.
  let subscribed = false
  let subscribing = false
  let lastAttemptAt = 0
  /** Bumped by every teardown, so a subscribe still in flight cannot latch state onto the torn-down subscription. */
  let subscribeGen = 0
  const ensureSubscribed = (opportunistic: boolean) => {
    if (subscribed || subscribing) return
    const now = Date.now()
    if (opportunistic) {
      if (lastAttemptAt === 0) return
      if (now - lastAttemptAt < RESUBSCRIBE_MIN_INTERVAL_MS) return
    }
    lastAttemptAt = now
    subscribing = true
    const gen = ++subscribeGen
    try {
      void Promise.resolve(
        config.client.subscribe(channel, (message) => {
          const parsed = parseIncoming<TRole>(
            message,
            secret,
            channel,
            warnDropOnce,
            acceptLegacyUnbound,
            seenEnvelopes,
          )
          // NOTE: skip our own messages by instance id; local caches are already cleared.
          if (!parsed || parsed.instanceId === instanceId) return
          // Guard each handler: engines sharing an invalidator must not miss a revoke because another threw.
          for (const h of handlers) {
            try {
              h(parsed.event)
            } catch (err) {
              console.error('[@gentleduck/iam:invalidator:redis] invalidation handler threw - continuing', err)
            }
          }
        }),
      )
        .then(() => {
          if (gen === subscribeGen) subscribed = true
        })
        .catch(reportSubscribeFailure)
        .finally(() => {
          if (gen === subscribeGen) subscribing = false
        })
    } catch (err) {
      // A client that throws synchronously never produces a promise.
      subscribing = false
      reportSubscribeFailure(err)
    }
  }

  return {
    publish(event) {
      let payload: string
      if (secret !== null) {
        // SECURITY: sign the channel too; on a shared secret a signature alone only proves "some tenant".
        const inner = { channel, event, instanceId, ts: Date.now() }
        const sig = createHmac('sha256', secret).update(signingPreimage(inner)).digest('hex')
        const envelope: SignedEnvelope<TRole> = { payload: inner, sig, v: ENVELOPE_V }
        payload = JSON.stringify(envelope)
      } else {
        payload = JSON.stringify({ event, instanceId })
      }
      // Non-fatal, but reported so a long outage does not desync nodes unnoticed.
      const reportPublishFailure = (err: unknown): void => {
        const error = err instanceof Error ? err : new Error(String(err))
        try {
          config.onPublishError?.(error, channel)
        } catch {
          /* operator hook itself threw - preserve fail-soft contract */
        }
        if (!config.onPublishError) {
          // Separate budget from inbound drops; see `reportDrop`.
          reportDrop('publish', channel, `publish failed (${error.message})`)
        }
      }
      // Retry a failed subscribe here; a no-op unless one was already attempted and failed.
      ensureSubscribed(true)
      try {
        const result = config.client.publish(channel, payload)
        // NOTE: ioredis rejects rather than throws; left unhandled, that crashes Node under
        // `--unhandled-rejections=throw`.
        if (isThenable(result)) result.then(undefined, reportPublishFailure)
      } catch (err) {
        reportPublishFailure(err)
      }
    },
    status() {
      return { subscribed }
    },
    subscribe(handler) {
      ensureSubscribed(false)
      handlers.add(handler)
      return () => {
        handlers.delete(handler)
        if (handlers.size === 0) {
          subscribed = false
          // A subscribe still in flight would otherwise latch `subscribed` back on and leave `subscribing` set,
          // so the next `subscribe()` returns early and never re-registers with the client.
          subscribing = false
          subscribeGen++
          // Catch an async rejection, as in `publish`. A failed teardown only warns; there is no hook for it.
          const unsubscribed = config.client.unsubscribe?.(channel)
          if (isThenable(unsubscribed)) {
            unsubscribed.then(undefined, (err: unknown) => {
              console.warn(
                `[@gentleduck/iam:invalidator:redis] unsubscribe from ${JSON.stringify(redactChannel(channel))} failed`,
                err,
              )
            })
          }
        }
      }
    },
  }
}

/**
 * Decodes and verifies an inbound message into `{ instanceId, event }`, or reports the drop and returns `null`.
 * SECURITY: a secret admits only verified, in-window envelopes; no secret admits only the unsigned legacy shape.
 */
function parseIncoming<TRole extends string>(
  s: string,
  secret: string | null,
  channel: string,
  warnDropOnce: (channel: string, reason: string) => void,
  acceptLegacyUnbound: boolean,
  seenEnvelopes: ISeenEnvelopes | null,
): { instanceId: string; event: IamEngineTypes.IInvalidateEvent<TRole> } | null {
  if (typeof s !== 'string') return null
  // SECURITY: pre-auth size cap in UTF-8 bytes; `s.length` undercounts multi-byte text.
  if (Buffer.byteLength(s, 'utf8') > MAX_WIRE_BYTES) {
    warnDropOnce(channel, 'oversize wire message')
    return null
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(s)
  } catch {
    if (secret !== null) warnDropOnce(channel, 'invalid JSON')
    return null
  }
  if (typeof parsed !== 'object' || parsed === null) return null
  // Depth/key cap, so `canonicalJSON` below is safe on hostile input.
  if (_measurePayload(parsed) === null) {
    warnDropOnce(channel, 'payload exceeds depth/key limits')
    return null
  }

  const wireVersion = Reflect.get(parsed, 'v')
  const isUnbound = wireVersion === ENVELOPE_V_UNBOUND

  // Signed envelope path.
  if (wireVersion === ENVELOPE_V || isUnbound) {
    // SECURITY: unverifiable without a secret, and a forged `instanceId` would suppress real events.
    // Checked before the version so the reason names the misconfiguration.
    if (secret === null) {
      warnDropOnce(channel, `v:${String(wireVersion)} envelope received without secret configured`)
      return null
    }
    if (isUnbound && !acceptLegacyUnbound) {
      // Correctly signed, but the signature does not name its channel.
      warnDropOnce(channel, `v:${ENVELOPE_V_UNBOUND} envelope is not channel-bound`)
      return null
    }
    const sig = Reflect.get(parsed, 'sig')
    const payload = Reflect.get(parsed, 'payload')
    if (typeof sig !== 'string' || typeof payload !== 'object' || payload === null) {
      warnDropOnce(channel, 'malformed envelope')
      return null
    }
    // SECURITY: `payload` is already round-tripped, matching `signingPreimage`; compared in constant time.
    const expected = createHmac('sha256', secret).update(canonicalJSON(payload)).digest('hex')
    if (!safeHexEqual(sig, expected)) {
      warnDropOnce(channel, 'signature mismatch')
      return null
    }
    // SECURITY: a valid signature only proves the sender holds the secret, so the signed channel must be this one.
    if (!isUnbound) {
      const signedChannel = Reflect.get(payload, 'channel')
      if (typeof signedChannel !== 'string') {
        warnDropOnce(channel, 'malformed inner payload (channel)')
        return null
      }
      if (signedChannel !== channel) {
        warnDropOnce(channel, 'envelope was signed for a different channel')
        return null
      }
    }
    // Replay window check.
    const ts = Reflect.get(payload, 'ts')
    if (typeof ts !== 'number' || !Number.isFinite(ts)) {
      warnDropOnce(channel, 'missing or invalid ts')
      return null
    }
    const age = Date.now() - ts
    if (age > REPLAY_WINDOW_MS || age < -REPLAY_WINDOW_MS) {
      warnDropOnce(channel, 'replay window exceeded')
      return null
    }
    // SECURITY: in-window verbatim replay. The signature covers the payload, so the same one twice is the same
    // publish twice, and anyone with channel access could otherwise repeat it for the whole window.
    if (seenEnvelopes !== null && !seenEnvelopes.accept(sig, Date.now())) {
      warnDropOnce(channel, 'replayed envelope (this signature was already applied)')
      return null
    }
    // Shape-check inner payload.
    const instanceId = Reflect.get(payload, 'instanceId')
    if (typeof instanceId !== 'string') {
      warnDropOnce(channel, 'malformed inner payload (instanceId)')
      return null
    }
    const ev = Reflect.get(payload, 'event')
    if (!_isValidEvent<TRole>(ev)) {
      warnDropOnce(channel, 'malformed inner payload (event)')
      return null
    }
    return { event: ev, instanceId }
  }

  // Legacy unsigned envelope: only allowed when no secret is configured.
  if (secret !== null) {
    warnDropOnce(channel, 'unsigned message with secret configured')
    return null
  }
  const legacyInstanceId = Reflect.get(parsed, 'instanceId')
  if (typeof legacyInstanceId !== 'string') {
    warnDropOnce(channel, 'malformed legacy payload (instanceId)')
    return null
  }
  const ev = Reflect.get(parsed, 'event')
  if (!_isValidEvent<TRole>(ev)) {
    warnDropOnce(channel, 'malformed legacy payload (event)')
    return null
  }
  return { event: ev, instanceId: legacyInstanceId }
}

/** Per-kind shape check for an invalidate event: `subjectId` required, `roleId` optional, neither empty. */
function _isValidEvent<TRole extends string>(ev: unknown): ev is IamEngineTypes.IInvalidateEvent<TRole> {
  if (typeof ev !== 'object' || ev === null || Array.isArray(ev)) return false
  const kind = Reflect.get(ev, 'kind')
  if (kind === 'all' || kind === 'policies') return true
  if (kind === 'roles') {
    const roleId = Reflect.get(ev, 'roleId')
    return roleId === undefined || (typeof roleId === 'string' && roleId.length > 0)
  }
  if (kind === 'subject') {
    const subjectId = Reflect.get(ev, 'subjectId')
    return typeof subjectId === 'string' && subjectId.length > 0
  }
  return false
}

function generateInstanceId(): string {
  if (typeof globalThis.crypto?.randomUUID === 'function') return globalThis.crypto.randomUUID()
  return `iam-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
}
