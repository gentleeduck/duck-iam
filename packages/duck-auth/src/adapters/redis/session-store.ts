import { AuthErrorObject } from '../../core/errors'
import type { Session } from '../../core/types/session'
import type { RedisLike } from './redis-like'

export namespace RedisSessionStore {
  /** Config knobs for {@link RedisSessionStore}. */
  export interface IConfig {
    /** RedisLike client (ioredis, @upstash/redis, or FakeRedis). */
    redis: RedisLike.IClient
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
 * Redis-backed `Session.IStore`. Session.id is already the sha-256 of
 * the plaintext sid (see SessionsFacet) so the primary key + lookup
 * key are the same value.
 */
export class RedisSessionStore implements Session.IStore {
  private readonly _redis: RedisLike.IClient
  private readonly _prefix: string
  private readonly _maxTtlSec: number

  constructor(cfg: RedisSessionStore.IConfig) {
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

  private _ttlFor(session: Session.ISession): number {
    const remainingMs = Math.max(0, session.absoluteExpiresAt - Date.now())
    const remainingSec = Math.ceil(remainingMs / 1000)
    return Math.max(1, Math.min(this._maxTtlSec, remainingSec))
  }

  async create(s: Session.ISession): Promise<void> {
    if (!s.id) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'RedisSessionStore.create requires session.id to be set (sha-256 of sid)',
      })
    }
    const ttl = this._ttlFor(s)
    await this._redis.set(this._sessKey(s.id), JSON.stringify(s), { ex: ttl })
    if (s.identityId) {
      await this._redis.sadd(this._idxKey(s.identityId), s.id)
      await this._redis.expire(this._idxKey(s.identityId), this._maxTtlSec)
    }
  }

  async getByHash(sidHash: string): Promise<Session.ISession | null> {
    const raw = await this._redis.get(this._sessKey(sidHash))
    if (!raw) return null
    return parseStoredSession(raw)
  }

  async update(id: string, patch: Partial<Session.ISession>): Promise<Session.ISession> {
    const raw = await this._redis.get(this._sessKey(id))
    if (!raw) {
      throw new AuthErrorObject('AUTH/SESSION_REVOKED', { reason: `session ${id} not found` })
    }
    const current = parseStoredSession(raw)
    if (!current) {
      throw new AuthErrorObject('AUTH/SESSION_REVOKED', { reason: `session ${id} corrupted` })
    }
    const next: Session.ISession = { ...current, ...patch }
    const ttl = this._ttlFor(next)
    await this._redis.set(this._sessKey(id), JSON.stringify(next), { ex: ttl })
    if (next.identityId) {
      await this._redis.expire(this._idxKey(next.identityId), this._maxTtlSec)
    }
    return next
  }

  async delete(id: string): Promise<void> {
    const raw = await this._redis.get(this._sessKey(id))
    await this._redis.del(this._sessKey(id))
    if (raw) {
      const session = parseStoredSession(raw)
      if (session?.identityId) {
        await this._redis.srem(this._idxKey(session.identityId), id)
      }
    }
  }

  async listByIdentity(identityId: string): Promise<Session.ISession[]> {
    const ids = await this._redis.smembers(this._idxKey(identityId))
    if (ids.length === 0) return []
    const out: Session.ISession[] = []
    const stale: string[] = []
    for (const id of ids) {
      const raw = await this._redis.get(this._sessKey(id))
      if (raw) {
        const parsed = parseStoredSession(raw)
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

  // gc impl below

  async gc(_now: number): Promise<{ deleted: number }> {
    let cursor = '0'
    let deleted = 0
    do {
      const [next, keys] = await this._redis.scan(cursor, {
        match: `${this._prefix}:idx:identity:*`,
        count: 250,
      })
      cursor = next
      for (const idxKey of keys) {
        const ids = await this._redis.smembers(idxKey)
        const stale: string[] = []
        for (const id of ids) {
          const exists = await this._redis.get(this._sessKey(id))
          if (!exists) stale.push(id)
        }
        if (stale.length > 0) {
          deleted += await this._redis.srem(idxKey, ...stale)
        }
      }
    } while (cursor !== '0')
    return { deleted }
  }
}

/** Structural validator for a stored Redis session; SEC-critical fields enforced, rest is trusted. */
function parseStoredSession(raw: string): Session.ISession | null {
  let obj: unknown
  try {
    obj = JSON.parse(raw)
  } catch {
    return null
  }
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) return null
  const id: unknown = Reflect.get(obj, 'id')
  if (typeof id !== 'string' || id.length === 0) return null
  const expiresAt: unknown = Reflect.get(obj, 'expiresAt')
  if (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt)) return null
  const absoluteExpiresAt: unknown = Reflect.get(obj, 'absoluteExpiresAt')
  if (typeof absoluteExpiresAt !== 'number' || !Number.isFinite(absoluteExpiresAt)) return null
  return obj as Session.ISession
}
