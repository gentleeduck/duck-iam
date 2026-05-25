import { createHmac, timingSafeEqual } from 'node:crypto'
import type { EngineTypes } from '../../core/engine/engine.types'

/**
 * Redis invalidator integration types. Type-only namespace - zero bundle cost.
 *
 * @author wildduck2 <https://github.com/wildduck2>
 */
export namespace RedisInvalidator {
  /**
   * Describes the minimum pub/sub surface needed by the Redis invalidator.
   *
   * Both ioredis and node-redis v4+ implement this shape; call sites stay
   * intentionally narrow to avoid pulling in either as a hard dependency.
   * Pass two clients - Redis requires a separate connection per subscriber.
   *
   * @author wildduck2 <https://github.com/wildduck2>
   */
  export interface IPubSubLike {
    /**
     * Publishes the JSON payload on the given channel for every local admin
     * mutation. Synchronous return is fine; the caller does not await.
     *
     * @param channel - Names the channel to publish on.
     * @param message - Serialised JSON payload to broadcast.
     * @returns Whatever the underlying client returns; ignored by the invalidator.
     * @author wildduck2 <https://github.com/wildduck2>
     */
    publish(channel: string, message: string): unknown
    /**
     * Subscribes the handler to incoming messages on the channel. The factory
     * calls this once with the channel name and a raw-message handler.
     *
     * @param channel - Names the channel to subscribe to.
     * @param handler - Receives each raw message string from the channel.
     * @returns Void synchronously or a promise the caller may await on startup.
     * @author wildduck2 <https://github.com/wildduck2>
     */
    subscribe(channel: string, handler: (message: string) => void): void | Promise<void>
    /**
     * Tears down the subscription. Engine calls this on `dispose()`. Optional -
     * passing a no-op stub is fine if your client manages connection lifecycle
     * out of band.
     *
     * @param channel - Names the channel to detach from.
     * @returns Void synchronously or a promise.
     * @author wildduck2 <https://github.com/wildduck2>
     */
    unsubscribe?(channel: string): void | Promise<void>
  }

  /**
   * Configures {@link createRedisInvalidator}.
   *
   * @author wildduck2 <https://github.com/wildduck2>
   */
  export interface IConfig {
    /** Redis pub/sub adapter implementing {@link IPubSubLike}. */
    client: IPubSubLike
    /**
     * Channel name. Every engine subscribing to the same channel shares an
     * invalidate broadcast group. Defaults to `'duck-iam:invalidate'`. Use a
     * tenant-prefixed channel in multi-tenant deployments so tenants don't
     * cross-invalidate.
     */
    channel?: string
    /**
     * Shared HMAC secret. When set, every published envelope is signed with
     * `HMAC-SHA256(secret, canonicalJSON(payload))` and incoming envelopes
     * without a verifying signature are dropped (silent — one `console.warn`
     * per channel on the first rejection). When `null` or omitted (default),
     * the invalidator falls back to legacy unsigned envelopes and warns once
     * at construction. Any party with PUBLISH rights to the channel can wipe
     * caches in that mode; set a secret in production.
     */
    secret?: string | null
  }
}

/**
 * @deprecated Use {@link RedisInvalidator.IPubSubLike}. Will be removed in 3.0.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export type IRedisPubSubLike = RedisInvalidator.IPubSubLike

/**
 * @deprecated Use {@link RedisInvalidator.IConfig}. Will be removed in 3.0.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export type IRedisInvalidatorConfig = RedisInvalidator.IConfig

const DEFAULT_CHANNEL = 'duck-iam:invalidate'

/** Replay window in milliseconds. Signed envelopes older than this are dropped. */
const REPLAY_WINDOW_MS = 30_000

/** Wire-format version. Bump when the envelope shape changes incompatibly. */
const ENVELOPE_V = 1

/** Module-level latch for the unsigned-mode warning. Fires at most once per process. */
const _UNSIGNED_WARNED = { fired: false }

/**
 * SEC-032: per-channel rate-limited warn state. A previous one-shot latch
 * let an attacker burn the first warn on a benign reason (e.g. a stray
 * invalid-JSON probe) and then silently flood the channel with hostile
 * payloads. The current shape rate-limits warns at SEC-032-tunable
 * intervals and surfaces a coalesced suppressed-count so operators see
 * sustained abuse instead of silence.
 */
const _DROP_WARN_STATE = new Map<string, { lastWarn: number; suppressed: number }>()
/** Minimum gap between drop warns for a single channel. */
const DROP_WARN_WINDOW_MS = 60_000

/**
 * SEC-031 guard limits applied to incoming wire messages BEFORE the HMAC
 * verifier (i.e. pre-auth, so they must be cheap and stack-safe).
 */
const MAX_WIRE_BYTES = 16 * 1024
const MAX_PAYLOAD_DEPTH = 8
const MAX_PAYLOAD_KEYS = 64
/** Depth-of-defence cap on {@link canonicalJSON} recursion itself. */
const CANONICAL_MAX_DEPTH = 16

/**
 * Iterative walker counting nesting depth + total key count of an
 * already-parsed JSON value. Non-recursive so the guard itself cannot stack-
 * overflow even on adversarial input. Returns `null` if either cap is
 * exceeded.
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
      const keys = Object.keys(node as Record<string, unknown>)
      totalKeys += keys.length
      if (totalKeys > MAX_PAYLOAD_KEYS) return null
      const obj = node as Record<string, unknown>
      for (const key of keys) {
        const child = obj[key]
        if (child !== null && typeof child === 'object') stack.push([child, depth + 1])
      }
    }
  }
  return { depth: maxDepth, keys: totalKeys }
}

/**
 * Canonical JSON serializer with stable key order. Used as the HMAC pre-image
 * so publisher and verifier agree on the exact byte string regardless of how
 * the host JSON engine orders object keys. Arrays preserve order; objects sort
 * keys lexicographically.
 *
 * SEC-031 defence in depth: bounded recursion. Callers in the verify path
 * additionally enforce a depth/size/key-count guard on the parsed payload
 * before invoking this function — `_depth` here protects the publish path
 * and any future caller that bypasses the wire guard.
 */
function canonicalJSON(v: unknown, _depth = 0): string {
  if (_depth > CANONICAL_MAX_DEPTH) throw new Error('canonicalJSON: max depth exceeded')
  if (v === null || typeof v !== 'object') return JSON.stringify(v)
  if (Array.isArray(v)) return `[${v.map((x) => canonicalJSON(x, _depth + 1)).join(',')}]`
  const keys = Object.keys(v as Record<string, unknown>).sort()
  const obj = v as Record<string, unknown>
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJSON(obj[k], _depth + 1)}`).join(',')}}`
}

/**
 * Internal envelope produced by the publisher. Wire layout:
 *   { v: 1, sig: <hex>, payload: { instanceId, event, ts } }
 * For unsigned mode, the legacy shape `{ instanceId, event }` is used.
 */
interface SignedEnvelope<TRole extends string> {
  readonly v: 1
  readonly sig: string
  readonly payload: {
    readonly instanceId: string
    readonly event: EngineTypes.IInvalidateEvent<TRole>
    readonly ts: number
  }
}

/**
 * Constant-time hex string compare. Wraps Buffer construction so callers don't
 * have to handle length mismatch (which would short-circuit `timingSafeEqual`
 * and leak a timing oracle on signature length).
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
  if (ab.length !== bb.length || ab.length === 0) return false
  return timingSafeEqual(ab, bb)
}

/**
 * Creates a cross-instance cache-invalidation broadcaster backed by Redis pub/sub.
 *
 * Delivery is at-least-once: every engine's local invalidate methods are
 * idempotent so re-applying the same event is safe. Filters self-published
 * events via an instance UUID embedded in the payload - without this guard
 * every local invalidate would echo back through the subscriber and re-clear
 * caches we just rebuilt.
 *
 * When `init.secret` is set, envelopes are signed with HMAC-SHA256 and
 * verified on receive with a 30-second replay window keyed off `payload.ts`.
 * Without a secret the invalidator falls back to legacy unsigned envelopes
 * (logged once); anyone with PUBLISH rights on the channel can then wipe
 * caches → set a secret in production.
 *
 * @template TRole - Role identifier union the engine is parameterised over.
 * @param config - Supplies the client and optional channel; see {@link RedisInvalidator.IConfig}.
 * @returns An {@link EngineTypes.IInvalidator} bound to the configured channel.
 * @example
 * ```ts
 * import { createRedisInvalidator } from '@gentleduck/iam/invalidators/redis'
 *
 * const engine = new Engine({
 *   adapter,
 *   invalidator: createRedisInvalidator({
 *     client: redisPubSub,
 *     secret: process.env.IAM_INVALIDATE_SECRET,
 *   }),
 * })
 * ```
 * @author wildduck2 <https://github.com/wildduck2>
 */
export function createRedisInvalidator<TRole extends string = string>(
  config: RedisInvalidator.IConfig,
): EngineTypes.IInvalidator<TRole> {
  const channel = config.channel ?? DEFAULT_CHANNEL
  const instanceId = generateInstanceId()
  const handlers = new Set<(event: EngineTypes.IInvalidateEvent<TRole>) => void>()
  const secret = config.secret ?? null

  if (secret === null && !_UNSIGNED_WARNED.fired) {
    _UNSIGNED_WARNED.fired = true
    console.warn(
      'duck-iam createRedisInvalidator: `secret` not set — accepting unsigned pub/sub. Anyone with PUBLISH rights on the channel can wipe caches. Pass `secret` to require HMAC-SHA256.',
    )
  }

  function warnDropOnce(channelName: string, reason: string): void {
    const now = Date.now()
    const state = _DROP_WARN_STATE.get(channelName)
    if (!state) {
      _DROP_WARN_STATE.set(channelName, { lastWarn: now, suppressed: 0 })
      console.warn(
        `duck-iam createRedisInvalidator: dropping unverifiable message on channel ${JSON.stringify(channelName)} (${reason}). Further drops within ${DROP_WARN_WINDOW_MS}ms are coalesced.`,
      )
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
    console.warn(
      `duck-iam createRedisInvalidator: dropping unverifiable message on channel ${JSON.stringify(channelName)} (${reason}). ${suppressed} prior drops coalesced.`,
    )
  }

  let subscribed = false
  const ensureSubscribed = () => {
    if (subscribed) return
    subscribed = true
    void Promise.resolve(
      config.client.subscribe(channel, (message) => {
        const parsed = parseIncoming<TRole>(message, secret, channel, warnDropOnce)
        // Drop messages that originated on this instance - local mutations
        // already cleared local caches; replaying would just double the work
        // and risk an invalidation storm under high write QPS.
        if (!parsed || parsed.instanceId === instanceId) return
        for (const h of handlers) h(parsed.event)
      }),
    )
  }

  return {
    publish(event) {
      let payload: string
      if (secret !== null) {
        const inner = { event, instanceId, ts: Date.now() }
        const sig = createHmac('sha256', secret).update(canonicalJSON(inner)).digest('hex')
        const envelope: SignedEnvelope<TRole> = { payload: inner, sig, v: ENVELOPE_V }
        payload = JSON.stringify(envelope)
      } else {
        payload = JSON.stringify({ event, instanceId })
      }
      try {
        config.client.publish(channel, payload)
      } catch {
        // Publish failure is non-fatal: local invalidate already applied,
        // remote nodes will pick up the change on TTL. Swallowing matches
        // the same fail-soft contract used by `engine.hooks.onError`.
      }
    },
    subscribe(handler) {
      ensureSubscribed()
      handlers.add(handler)
      return () => {
        handlers.delete(handler)
        if (handlers.size === 0) {
          subscribed = false
          void config.client.unsubscribe?.(channel)
        }
      }
    },
  }
}

/**
 * Decodes and validates an incoming wire message.
 *
 * When `secret` is `null` we accept legacy `{instanceId, event}` only. v:1
 * envelopes are dropped in unsigned mode — accepting them without verifying
 * the HMAC would let an attacker forge the `instanceId` field, which the
 * self-filter uses to ignore own-process replays. A forged match would
 * suppress legitimate cross-instance invalidations (SEC-046). When `secret`
 * is set we require a v:1 envelope, verify the HMAC, and enforce the replay
 * window. Anything else is dropped silently after a one-shot warn per channel.
 *
 * Returned shape is normalized to `{instanceId, event}` so the caller doesn't
 * branch on wire format.
 */
function parseIncoming<TRole extends string>(
  s: string,
  secret: string | null,
  channel: string,
  warnDropOnce: (channel: string, reason: string) => void,
): { instanceId: string; event: EngineTypes.IInvalidateEvent<TRole> } | null {
  // SEC-031: pre-auth size cap. canonicalJSON runs BEFORE the HMAC verify,
  // so an unauth peer could otherwise crash subscribers with deeply nested
  // JSON. Reject oversize wire messages before JSON.parse so we never
  // allocate the parse tree for a hostile blob.
  if (typeof s !== 'string') return null
  // SEC-034: cap by UTF-8 byte length, not `s.length` (which counts UTF-16
  // code units). A surrogate-heavy string would otherwise sneak ~4x past the
  // 16KB cap and force the JSON parser to materialise a much larger tree.
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
  // SEC-031: depth + key-count cap on the parsed tree, using an iterative
  // walker that can't stack-overflow itself. Applied to every incoming
  // envelope (both legacy and v:1) so the canonicalJSON pre-image is always
  // safe to materialise.
  if (_measurePayload(parsed) === null) {
    warnDropOnce(channel, 'payload exceeds depth/key limits')
    return null
  }
  const obj = parsed as Record<string, unknown>

  // v:1 signed envelope path
  if (obj.v === ENVELOPE_V) {
    // SEC-046: never honour a v:1 envelope without a secret. The signed-mode
    // envelope wraps `instanceId` inside a payload that is supposed to be
    // tamper-evident; unwrapping it without verifying would let an attacker
    // pick any `instanceId` (including a collision with the local instance's
    // UUID) and silence its own legitimate cross-instance invalidations.
    if (secret === null) {
      warnDropOnce(channel, 'v:1 envelope received without secret configured')
      return null
    }
    const sig = obj.sig
    const payload = obj.payload
    if (typeof sig !== 'string' || typeof payload !== 'object' || payload === null) {
      warnDropOnce(channel, 'malformed envelope')
      return null
    }
    // Verify signature against canonical pre-image. Use constant-time compare.
    const expected = createHmac('sha256', secret).update(canonicalJSON(payload)).digest('hex')
    if (!safeHexEqual(sig, expected)) {
      warnDropOnce(channel, 'signature mismatch')
      return null
    }
    // Replay window check.
    const ts = (payload as { ts?: unknown }).ts
    if (typeof ts !== 'number' || !Number.isFinite(ts)) {
      warnDropOnce(channel, 'missing or invalid ts')
      return null
    }
    const age = Date.now() - ts
    if (age > REPLAY_WINDOW_MS || age < -REPLAY_WINDOW_MS) {
      warnDropOnce(channel, 'replay window exceeded')
      return null
    }
    // Shape-check inner payload.
    const inner = payload as Record<string, unknown>
    if (typeof inner.instanceId !== 'string') return null
    const ev = inner.event
    if (!_isValidEvent(ev)) return null
    return { event: ev as EngineTypes.IInvalidateEvent<TRole>, instanceId: inner.instanceId }
  }

  // Legacy unsigned envelope: only allowed when no secret is configured.
  if (secret !== null) {
    warnDropOnce(channel, 'unsigned message with secret configured')
    return null
  }
  if (typeof obj.instanceId !== 'string') return null
  const ev = obj.event
  if (!_isValidEvent(ev)) return null
  return { event: ev as EngineTypes.IInvalidateEvent<TRole>, instanceId: obj.instanceId }
}

/**
 * Returns `true` when `ev` matches the {@link EngineTypes.IInvalidateEvent}
 * discriminated union. Tighter than a bare `typeof === 'object'` check so a
 * tampered payload can't trigger arbitrary handler calls.
 */
function _isValidEvent(ev: unknown): boolean {
  if (typeof ev !== 'object' || ev === null) return false
  const kind = (ev as { kind?: unknown }).kind
  return kind === 'all' || kind === 'policies' || kind === 'roles' || kind === 'subject'
}

function generateInstanceId(): string {
  if (typeof globalThis.crypto?.randomUUID === 'function') return globalThis.crypto.randomUUID()
  return `iam-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
}
