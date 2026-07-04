import { AuthError } from '../../core/errors'
import type { Session } from '../../core/types/session'
import { AUTH_SESSION_FACTOR_METHODS, AUTH_SESSION_KINDS } from '../../core/types/session'
import type { RedisLike } from './redis-like'

export namespace RedisSessionStore {
  /** Config knobs for {@link RedisSessionStore}. */
  export type Config<TRedis extends RedisLike.Client = RedisLike.Client> = {
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
export class RedisSessionStore<TRedis extends RedisLike.Client = RedisLike.Client> implements Session.Store {
  private readonly _redis: TRedis
  private readonly _prefix: string
  private readonly _maxTtlSec: number

  constructor(cfg: RedisSessionStore.Config<TRedis>) {
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

  private _ttlFor(session: Session.Me): number {
    const absMs =
      session.absoluteExpiresAt instanceof Date ? session.absoluteExpiresAt.getTime() : session.absoluteExpiresAt
    const remainingMs = Math.max(0, absMs - Date.now())
    const remainingSec = Math.ceil(remainingMs / 1000)
    return Math.max(1, Math.min(this._maxTtlSec, remainingSec))
  }

  async create(s: Session.Me): Promise<void> {
    if (!s.id) {
      throw new AuthError('AUTH_MISCONFIGURED', {
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

  async getByHash(sidHash: string): Promise<Session.Me | null> {
    const raw = await this._redis.get(this._sessKey(sidHash))
    if (!raw) return null
    return parseStoredSession(raw)
  }

  async update(id: string, patch: Partial<Session.Me>): Promise<Session.Me> {
    const raw = await this._redis.get(this._sessKey(id))
    if (!raw) {
      throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })
    }
    const current = parseStoredSession(raw)
    if (!current) {
      throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} corrupted` })
    }
    const next: Session.Me = { ...current, ...patch }
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

  async listByIdentity(identityId: string): Promise<Session.Me[]> {
    const ids = await this._redis.smembers(this._idxKey(identityId))
    if (ids.length === 0) return []
    const out: Session.Me[] = []
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

/** Structural validator for a stored Redis session; SEC-critical fields enforced, rest is trusted. */
function parseStoredSession(raw: string): Session.Me | null {
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

  const kind = AUTH_SESSION_KINDS.includes(obj.kind as Session.Kind) ? (obj.kind as Session.Kind) : null
  if (!kind) return null

  const rawAal = obj.aal
  const aal: Session.AAL | null = rawAal === 1 || rawAal === 2 || rawAal === 3 ? rawAal : null
  if (!aal) return null

  const expiresAtDate = parseStoredDate(obj.expiresAt)
  if (!expiresAtDate) return null
  const absoluteExpiresAtDate = parseStoredDate(obj.absoluteExpiresAt)
  if (!absoluteExpiresAtDate) return null
  const createdAtDate = parseStoredDate(obj.createdAt) ?? expiresAtDate
  const rotatedAtDate = parseStoredDate(obj.rotatedAt) ?? expiresAtDate

  // Reconstitute factors — completedAt may be an ISO string (JSON-serialized Date)
  const rawFactors = Array.isArray(obj.factors) ? obj.factors : []
  const factors: Session.Factor[] = rawFactors
    .filter((f) => AUTH_SESSION_FACTOR_METHODS.includes(f.method))
    .map((f) => ({
      method: f.method,
      completedAt: parseStoredDate(f.completedAt) ?? createdAtDate,
    }))

  // Reconstitute actingAs if present
  let actingAs: Session.ActingAs | undefined
  if (typeof obj.actingAs === 'object' && obj.actingAs !== null && !Array.isArray(obj.actingAs)) {
    const raw = obj.actingAs as Record<string, unknown>
    const startedAt = parseStoredDate(raw.startedAt)
    const actingExpiresAt = parseStoredDate(raw.expiresAt)
    if (typeof raw.realIdentityId === 'string' && typeof raw.reason === 'string' && startedAt && actingExpiresAt) {
      actingAs = { realIdentityId: raw.realIdentityId, reason: raw.reason, startedAt, expiresAt: actingExpiresAt }
    }
  }

  const session: Session.Me = {
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
