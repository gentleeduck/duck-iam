import type { RedisLike } from '~/adapters/redis/redis-like'
import { AuthError } from '~/core/errors'
import { stripUndefined } from '~/core/patch'
import type { Sessions } from '~/core/sessions/sessions.types'
import { AUTH_SESSION_FACTOR_METHODS, AUTH_SESSION_KINDS } from '~/core/sessions/sessions.types'

export namespace RedisSession {
  /** Cfg knobs for {@link RedisSessionImpl}. */
  export type Cfg<TRedis extends RedisLike.Client = RedisLike.Client> = {
    /** RedisLike client (ioredis, @upstash/redis, or FakeRedis). */
    redis: TRedis
    /**
     * Key namespace prefix. Default: `auth`. Final keys:
     *   `${prefix}:sess:{sessionId}`
     *   `${prefix}:idx:identity:{identityId}` (Set of sessionId hashes)
     */
    prefix?: string
    /**
     * TTL safety cap applied to every session write. The session's own
     * `absoluteExpiresAt` is authoritative; this is a defense-in-depth
     * ceiling. Default: 30 days.
     */
    maxTtlSec?: number
  }
}

/**
 * Redis-backed `Session.Store`. Session.id is already the sha-256 of
 * the plaintext sid (see SessionsFacet) so the primary key + lookup
 * key are the same value.
 */
export class RedisSessionImpl<TRedis extends RedisLike.Client = RedisLike.Client> implements Sessions.Store {
  private readonly _redis: TRedis
  private readonly _prefix: string
  private readonly _maxTtlSec: number

  constructor(cfg: RedisSession.Cfg<TRedis>) {
    this._redis = cfg.redis
    this._prefix = cfg.prefix ?? 'auth'
    this._maxTtlSec = cfg.maxTtlSec ?? 30 * 24 * 60 * 60
  }

  private _sessKey(sessionId: string): string {
    return `${this._prefix}:sess:${sessionId}`
  }

  private _idxKey(identityId: string): string {
    return `${this._prefix}:idx:identity:${identityId}`
  }

  private _ttlFor(session: Sessions.Me): number {
    const absMs =
      session.absoluteExpiresAt instanceof Date ? session.absoluteExpiresAt.getTime() : session.absoluteExpiresAt
    const remainingMs = Math.max(0, absMs - Date.now())
    const remainingSec = Math.ceil(remainingMs / 1000)
    return Math.max(1, Math.min(this._maxTtlSec, remainingSec))
  }

  async create(s: Sessions.Me): Promise<void> {
    if (!s.id) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'RedisSessionStore.create requires session.id to be set (sha-256 of sid)',
      })
    }
    const ttl = this._ttlFor(s)
    // `nx`, because a session id is a primary key. Every SQL dialect raises a
    // unique violation on a duplicate insert; a plain `SET` overwrote the
    // existing session and returned as though it had created one, so a caller
    // that reused an id silently destroyed a live session instead of hearing
    // about the collision.
    const stored = await this._redis.set(this._sessKey(s.id), JSON.stringify(s), { ex: ttl, nx: true })
    if (stored === null) {
      throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${s.id} already exists` })
    }
    if (s.identityId) {
      await this._redis.sadd(this._idxKey(s.identityId), s.id)
      await this._redis.expire(this._idxKey(s.identityId), this._maxTtlSec)
    }
  }

  async getByHash(sidHash: string): Promise<Sessions.Me | null> {
    const raw = await this._redis.get(this._sessKey(sidHash))
    if (!raw) return null
    return parseStoredSession(raw, sidHash)
  }

  async update(id: string, patch: Partial<Sessions.Me>): Promise<Sessions.Me> {
    const raw = await this._redis.get(this._sessKey(id))
    if (!raw) {
      throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })
    }
    const current = parseStoredSession(raw, id)
    if (!current) {
      throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} corrupted` })
    }
    // `id` is pinned to the key the row lives under, and `undefined` in a patch
    // means "leave this alone" rather than "clear it" - the same two rules the
    // memory and SQL stores follow. A patch that moved `id` would file the row
    // under a key that disagrees with its own body, and `revoke(next.id)` would
    // then delete a key that was never this session.
    const next: Sessions.Me = { ...current, ...stripUndefined(patch), id: current.id }
    const ttl = this._ttlFor(next)
    await this._redis.set(this._sessKey(id), JSON.stringify(next), { ex: ttl })
    // A patch that repoints the session at another identity has to move it
    // between the indexes too. Leaving it in the old set made the session
    // invisible to `listByIdentity` for its new owner and, worse, unreachable by
    // `deleteAllForIdentity` - a "sign out everywhere" that could not reach it.
    if (current.identityId !== next.identityId) {
      if (current.identityId) await this._redis.srem(this._idxKey(current.identityId), current.id)
      if (next.identityId) await this._redis.sadd(this._idxKey(next.identityId), current.id)
    }
    if (next.identityId) {
      await this._redis.expire(this._idxKey(next.identityId), this._maxTtlSec)
    }
    return next
  }

  async delete(id: string): Promise<void> {
    const raw = await this._redis.get(this._sessKey(id))
    await this._redis.del(this._sessKey(id))
    if (raw) {
      const session = parseStoredSession(raw, id)
      if (session?.identityId) {
        await this._redis.srem(this._idxKey(session.identityId), id)
      }
    }
  }

  async listByIdentity(identityId: string): Promise<Sessions.Me[]> {
    const ids = await this._redis.smembers(this._idxKey(identityId))
    if (ids.length === 0) return []
    const out: Sessions.Me[] = []
    const stale: string[] = []
    for (const id of ids) {
      const raw = await this._redis.get(this._sessKey(id))
      if (raw) {
        const parsed = parseStoredSession(raw, id)
        if (parsed) out.push(parsed)
        // Corrupted entries are skipped (fail-closed). Caller treats
        // the row as not-present; the next write replaces it.
      } else {
        stale.push(id)
      }
    }
    if (stale.length > 0) {
      await this._redis.srem(this._idxKey(identityId), ...stale)
    }
    return out
  }

  async deleteAllForIdentity(identityId: string): Promise<void> {
    const ids = await this._redis.smembers(this._idxKey(identityId))
    if (ids.length > 0) {
      await this._redis.del(...ids.map((id) => this._sessKey(id)))
    }
    await this._redis.del(this._idxKey(identityId))
  }

  /**
   * Reconcile the identity indexes and purge expired sessions. The key TTL is
   * derived from `absoluteExpiresAt` alone, so without this sweep nothing at the
   * storage layer ever enforces the sliding `expiresAt`.
   *
   * `deleted` counts each index member reconciled once, whether its record was
   * already gone or is removed here.
   *
   * Guest sessions carry no `identityId` and so sit in no index; their expiry
   * stays TTL-only.
   */
  async gc(now: number): Promise<{ deleted: number }> {
    let cursor = '0'
    let deleted = 0
    do {
      const [next, keys] = await this._redis.scan(cursor, {
        match: `${this._prefix}:idx:identity:*`,
        count: 250,
      })
      cursor = next
      // One scan page is bounded by `count`, so fanning out per key stays within a
      // sane concurrency envelope.
      const pruned = await Promise.all(
        keys.map(async (idxKey) => {
          const ids = await this._redis.smembers(idxKey)
          if (ids.length === 0) return 0
          const raws = await Promise.all(ids.map((id) => this._redis.get(this._sessKey(id))))
          const stale: string[] = []
          for (let i = 0; i < ids.length; i++) {
            const id = ids[i] as string
            const raw = raws[i]
            if (!raw) {
              stale.push(id)
              continue
            }
            const parsed = parseStoredSession(raw, id)
            // An unparseable row is corruption: drop it rather than leave a record
            // no reader can use.
            if (parsed === null || parsed.expiresAt.getTime() <= now || parsed.absoluteExpiresAt.getTime() <= now) {
              await this._redis.del(this._sessKey(id))
              stale.push(id)
            }
          }
          if (stale.length === 0) return 0
          return this._redis.srem(idxKey, ...stale)
        }),
      )
      for (const n of pruned) deleted += n
    } while (cursor !== '0')
    return { deleted }
  }
}

/** Parse a Date value stored as ISO string or number in JSON. Returns null if unparseable. */
function parseStoredDate(v: unknown): Date | null {
  if (v instanceof Date) return v
  if (typeof v === 'string') {
    const d = new Date(v)
    return Number.isFinite(d.getTime()) ? d : null
  }
  if (typeof v === 'number' && Number.isFinite(v)) return new Date(v)
  return null
}

/**
 * Structural validator for a stored Redis session; SEC-critical fields enforced,
 * rest is trusted.
 *
 * `expectedId` is the key the row was read under. Every field below fails
 * closed, and so does the row's agreement with its own key.
 */
function parseStoredSession(raw: string, expectedId: string): Sessions.Me | null {
  let obj: Record<string, unknown>
  try {
    const parsed = JSON.parse(raw)
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null
    obj = parsed
  } catch {
    return null
  }
  const id = obj.id
  if (typeof id !== 'string' || id.length === 0) return null
  // The body's `id` is what callers revoke by, and the key is where the row
  // actually lives. When they disagree the row is not this session, and acting
  // on it deletes some other key while leaving this one live - so a stale or
  // planted body could survive its own revocation.
  if (id !== expectedId) return null

  // `identityId` decides whose session this is. Coercing a non-string to `null`
  // quietly turned an authenticated session into a guest one: it belongs to
  // nobody, sits in no index, and `deleteAllForIdentity` can no longer reach it.
  if (obj.identityId !== undefined && obj.identityId !== null && typeof obj.identityId !== 'string') return null

  // Same shape of mistake with the opposite blast radius. A caller reads
  // `csrfHash` and skips the check when it is `null`, so coercing a corrupt
  // value to `null` did not degrade CSRF protection - it switched it off for
  // that session.
  if (obj.csrfHash !== undefined && obj.csrfHash !== null && typeof obj.csrfHash !== 'string') return null

  const kind = AUTH_SESSION_KINDS.includes(obj.kind as Sessions.Kind) ? (obj.kind as Sessions.Kind) : null
  if (!kind) return null

  const rawAal = obj.aal
  const aal: Sessions.AAL | null = rawAal === 1 || rawAal === 2 || rawAal === 3 ? rawAal : null
  if (!aal) return null

  const expiresAtDate = parseStoredDate(obj.expiresAt)
  if (!expiresAtDate) return null
  const absoluteExpiresAtDate = parseStoredDate(obj.absoluteExpiresAt)
  if (!absoluteExpiresAtDate) return null
  // These two fail closed like every field above them. They used to fall back to
  // `expiresAtDate`, which for a live session is by construction in the future -
  // and `rotatedAt` is exactly what the freshness gate measures against, so
  // `now - rotatedAt` went negative and the session read as *permanently* fresh.
  // A row with a missing or corrupt `rotatedAt` was waved through the step-up
  // that guards password changes and payouts, forever. A session we cannot date
  // is a session we cannot judge, so it does not resolve at all.
  const createdAtDate = parseStoredDate(obj.createdAt)
  if (!createdAtDate) return null
  const rotatedAtDate = parseStoredDate(obj.rotatedAt)
  if (!rotatedAtDate) return null

  // Reconstitute factors: completedAt may be an ISO string (JSON-serialized Date)
  const rawFactors = Array.isArray(obj.factors) ? obj.factors : []
  const factors: Sessions.Factor[] = rawFactors
    .filter((f) => AUTH_SESSION_FACTOR_METHODS.includes(f.method))
    .map((f) => ({
      method: f.method,
      completedAt: parseStoredDate(f.completedAt) ?? createdAtDate,
    }))

  // Reconstitute actingAs if present
  let actingAs: Sessions.ActingAs | undefined
  if (typeof obj.actingAs === 'object' && obj.actingAs !== null && !Array.isArray(obj.actingAs)) {
    const raw = obj.actingAs as Record<string, unknown>
    const startedAt = parseStoredDate(raw.startedAt)
    const actingExpiresAt = parseStoredDate(raw.expiresAt)
    if (typeof raw.realIdentityId === 'string' && typeof raw.reason === 'string' && startedAt && actingExpiresAt) {
      actingAs = { realIdentityId: raw.realIdentityId, reason: raw.reason, startedAt, expiresAt: actingExpiresAt }
    }
  }

  const session: Sessions.Me = {
    id,
    identityId: typeof obj.identityId === 'string' ? obj.identityId : null,
    tenantId: typeof obj.tenantId === 'string' ? obj.tenantId : null,
    kind,
    aal,
    factors,
    csrfHash: typeof obj.csrfHash === 'string' ? obj.csrfHash : null,
    ip: typeof obj.ip === 'string' ? obj.ip : null,
    userAgent: typeof obj.userAgent === 'string' ? obj.userAgent : null,
    fingerprint: typeof obj.fingerprint === 'string' ? obj.fingerprint : null,
    fresh: typeof obj.fresh === 'boolean' ? obj.fresh : false,
    createdAt: createdAtDate,
    rotatedAt: rotatedAtDate,
    expiresAt: expiresAtDate,
    absoluteExpiresAt: absoluteExpiresAtDate,
    actingAs: actingAs ?? null,
  }
  return session
}

/** Factory around {@link SessionImpl} for functional-style config. */
export function session<TRedis extends RedisLike.Client = RedisLike.Client>(
  cfg: RedisSession.Cfg<TRedis>,
): RedisSessionImpl<TRedis> {
  return new RedisSessionImpl(cfg)
}

/** Factory around {@link RedisSessionImpl}, for callers who prefer functions to `new`. */
export function redisSessionImpl(...args: ConstructorParameters<typeof RedisSessionImpl>): RedisSessionImpl {
  return new RedisSessionImpl(...args)
}
