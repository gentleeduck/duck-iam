/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../../core/errors'
import type { Session } from '../../core/types/session'
import type { RedisLike } from './redis-like'

/**
 * Config knobs for `RedisSessionStore`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface RedisSessionStoreConfig {
  /** RedisLike client (ioredis, @upstash/redis, or FakeRedis). */
  redis: RedisLike
  /**
   * Key namespace prefix. Default: `auth`. Final keys:
   *   `${prefix}:sess:{sessionId}`
   *   `${prefix}:idx:identity:{identityId}` (Set of sessionId hashes)
   */
  prefix?: string
  /**
   * TTL safety cap applied to every session write. The session's own
   * `absoluteExpiresAt` is authoritative; this is a defense-in-depth
   * ceiling so a buggy producer cannot create non-expiring keys.
   * Default: 30 days.
   */
  maxTtlSec?: number
}

/**
 * Redis-backed `Session.IStore`. Session.id is already the sha-256 of
 * the plaintext sid (see SessionsFacet) so the primary key + lookup
 * key are the same value; no second mapping is needed.
 *
 * Keys:
 *   - `${prefix}:sess:{sessionId}` -> JSON-encoded ISession
 *   - `${prefix}:idx:identity:{identityId}` -> Set of sessionId values
 *
 * GC: TTL handles the primary record. Identity Sets are reconciled
 * eagerly on `delete()` and lazily on `listByIdentity()` + `gc()`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class RedisSessionStore implements Session.IStore {
  private readonly _redis: RedisLike
  private readonly _prefix: string
  private readonly _maxTtlSec: number

  constructor(cfg: RedisSessionStoreConfig) {
    this._redis = cfg.redis
    this._prefix = cfg.prefix ?? 'auth'
    this._maxTtlSec = cfg.maxTtlSec ?? 30 * 24 * 60 * 60
  }

  /** Compose the primary session record key. */
  private _sessKey(sessionId: string): string {
    return `${this._prefix}:sess:${sessionId}`
  }

  /** Compose the identity -> sessionIds Set key. */
  private _idxKey(identityId: string): string {
    return `${this._prefix}:idx:identity:${identityId}`
  }

  /** Clamp the per-write TTL to `maxTtlSec`. */
  private _ttlFor(session: Session.ISession): number {
    const remainingMs = Math.max(0, session.absoluteExpiresAt - Date.now())
    const remainingSec = Math.ceil(remainingMs / 1000)
    return Math.max(1, Math.min(this._maxTtlSec, remainingSec))
  }

  /**
   * Persist a new session. Writes the primary record and, for identified
   * sessions, indexes the sessionId under the owning identity's Set.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
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

  /**
   * Read a session by its hash. Returns null when missing or TTL-expired.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async getByHash(sidHash: string): Promise<Session.ISession | null> {
    const raw = await this._redis.get(this._sessKey(sidHash))
    if (!raw) return null
    return JSON.parse(raw) as Session.ISession
  }

  /**
   * Patch an existing session in-place. TTL is recalculated from the
   * patched `absoluteExpiresAt` so a rotation does not silently extend
   * the original window past its cap.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async update(id: string, patch: Partial<Session.ISession>): Promise<Session.ISession> {
    const raw = await this._redis.get(this._sessKey(id))
    if (!raw) {
      throw new AuthErrorObject('AUTH/SESSION_REVOKED', { reason: `session ${id} not found` })
    }
    const current = JSON.parse(raw) as Session.ISession
    const next: Session.ISession = { ...current, ...patch }
    const ttl = this._ttlFor(next)
    await this._redis.set(this._sessKey(id), JSON.stringify(next), { ex: ttl })
    if (next.identityId) {
      await this._redis.expire(this._idxKey(next.identityId), this._maxTtlSec)
    }
    return next
  }

  /**
   * Hard-delete a session. Drops the primary record and removes the id
   * from the owning identity's Set (best-effort: reads the record first
   * so we know which Set to touch).
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async delete(id: string): Promise<void> {
    const raw = await this._redis.get(this._sessKey(id))
    await this._redis.del(this._sessKey(id))
    if (raw) {
      const session = JSON.parse(raw) as Session.ISession
      if (session.identityId) {
        await this._redis.srem(this._idxKey(session.identityId), id)
      }
    }
  }

  /**
   * Enumerate live sessions for an identity. Stale Set members (primary
   * record TTL-evicted) are pruned during the scan.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async listByIdentity(identityId: string): Promise<Session.ISession[]> {
    const ids = await this._redis.smembers(this._idxKey(identityId))
    if (ids.length === 0) return []
    const out: Session.ISession[] = []
    const stale: string[] = []
    for (const id of ids) {
      const raw = await this._redis.get(this._sessKey(id))
      if (raw) {
        out.push(JSON.parse(raw) as Session.ISession)
      } else {
        stale.push(id)
      }
    }
    if (stale.length > 0) {
      await this._redis.srem(this._idxKey(identityId), ...stale)
    }
    return out
  }

  /**
   * Revoke every session for an identity. Drops every live record + the
   * index Set in one pass.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async deleteAllForIdentity(identityId: string): Promise<void> {
    const ids = await this._redis.smembers(this._idxKey(identityId))
    if (ids.length > 0) {
      await this._redis.del(...ids.map((id) => this._sessKey(id)))
    }
    await this._redis.del(this._idxKey(identityId))
  }

  /**
   * Reconcile orphaned index entries left behind when a primary record
   * TTL-expires before its containing Set member is removed. Returns the
   * count of dropped Set members.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
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

/**
 * Namespace merge for `RedisSessionStore`. Co-locates the config shape
 * alongside the class via TS class+namespace merging.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace RedisSessionStore {
  /** Alias for `RedisSessionStoreConfig`. */
  export type IConfig = RedisSessionStoreConfig
}
