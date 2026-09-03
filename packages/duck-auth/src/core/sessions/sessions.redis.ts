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
     *   `${prefix}:exp` (ZSet of `sessionId:identityId`, scored by expiry)
     *   `${prefix}:gc:lease`
     */
    prefix?: string
    /**
     * TTL safety cap applied to every session write. The session's own
     * `absoluteExpiresAt` is authoritative; this is a defense-in-depth
     * ceiling. Default: 30 days.
     */
    maxTtlSec?: number
    /**
     * How long `gc` holds its exclusive lease. Long enough to cover a sweep,
     * short enough that a crashed holder frees it quickly. Default: 5 minutes.
     */
    gcLeaseSec?: number
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
  private readonly _gcLeaseSec: number

  constructor(cfg: RedisSession.Cfg<TRedis>) {
    this._redis = cfg.redis
    this._prefix = cfg.prefix ?? 'auth'
    this._maxTtlSec = cfg.maxTtlSec ?? 30 * 24 * 60 * 60
    this._gcLeaseSec = cfg.gcLeaseSec ?? 5 * 60
  }

  private _sessKey(sessionId: string): string {
    return `${this._prefix}:sess:${sessionId}`
  }

  private _idxKey(identityId: string): string {
    return `${this._prefix}:idx:identity:${identityId}`
  }

  private _leaseKey(): string {
    return `${this._prefix}:gc:lease`
  }

  /**
   * The expiry index: one sorted set for the whole deployment, scored by the
   * instant a session stops being usable. `gc` reads it instead of walking every
   * identity index, so a sweep costs one range query plus the rows it actually
   * removes - not a scan of every session that exists.
   */
  private _expKey(): string {
    return `${this._prefix}:exp`
  }

  /**
   * `sessionId:identityId`, so `gc` can remove a row from its owner's index
   * without reading the record first. A guest session carries an empty tail; it
   * still gets swept, which the identity-index walk this replaced could never do.
   *
   * The split is on the first `:`, which is why `create` refuses an id
   * containing one.
   */
  private _expMember(sessionId: string, identityId: string | null): string {
    return `${sessionId}:${identityId ?? ''}`
  }

  /** Inverse of {@link _expMember}. An identity may legitimately contain `:`; a session id may not. */
  private _parseExpMember(member: string): { sessionId: string; identityId: string | null } {
    const cut = member.indexOf(':')
    // No separator at all is not a member this class wrote. Treat the whole
    // string as the id and no identity: `del` and `srem` are both no-ops on
    // something that does not exist, so the sweep still clears the member.
    if (cut === -1) return { identityId: null, sessionId: member }
    const identityId = member.slice(cut + 1)
    return { identityId: identityId === '' ? null : identityId, sessionId: member.slice(0, cut) }
  }

  /**
   * Whichever deadline comes first. The Redis key TTL tracks `absoluteExpiresAt`
   * alone, so scoring on the minimum is what gives the sliding `expiresAt` a
   * storage-layer enforcer at all.
   */
  private _expScore(session: Pick<Sessions.Me, 'expiresAt' | 'absoluteExpiresAt'>): number {
    const abs = parseStoredDate(session.absoluteExpiresAt)
    const idle = parseStoredDate(session.expiresAt)
    // A row we cannot date is a row we cannot schedule. Score it as already due
    // rather than never: `gc` then drops it, which is the same fail-closed answer
    // `parseStoredSession` gives a reader.
    if (!abs && !idle) return 0
    return Math.min(abs?.getTime() ?? Number.POSITIVE_INFINITY, idle?.getTime() ?? Number.POSITIVE_INFINITY)
  }

  private _ttlFor(session: Pick<Sessions.Me, 'absoluteExpiresAt'>): number {
    // The parser the read path already uses, so a date that arrived serialised
    // yields the session's real TTL instead of the ceiling. The old branch
    // assumed anything that was not a `Date` was a number, so an ISO string made
    // every step below it `NaN` and `{ ex: NaN }` reached the client - which some
    // clients store as a key with no expiry at all, an immortal session.
    const abs = parseStoredDate(session.absoluteExpiresAt)
    // Fail closed on a value nothing can parse. The cap bounds the damage without
    // destroying a live session the way a 1-second floor would, and `resolveBySid`
    // still refuses the row if it really is stale.
    if (!abs) return this._maxTtlSec
    const remainingSec = Math.ceil(Math.max(0, abs.getTime() - Date.now()) / 1000)
    return Math.max(1, Math.min(this._maxTtlSec, remainingSec))
  }

  /**
   * Undo the index entry a failed `create` added - and only that one. `sadd`
   * reports whether it actually added, so a call that collided with an id already
   * in the set cannot remove the entry that was there first.
   */
  private async _unindex(identityId: string | null, sessionId: string, added: number): Promise<void> {
    // Best effort throughout: the record write has already failed, and losing a
    // compensation on top of it leaves an entry that names nothing, which every
    // reader skips and the index key's own TTL eventually takes.
    await this._redis.zrem(this._expKey(), this._expMember(sessionId, identityId)).catch(() => 0)
    if (!identityId || added === 0) return
    await this._redis.srem(this._idxKey(identityId), sessionId).catch(() => 0)
  }

  async create(s: Sessions.CreateInput): Promise<void> {
    if (!s.id) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'RedisSessionStore.create requires session.id to be set (sha-256 of sid)',
      })
    }
    // The expiry index packs `sessionId:identityId` into one member and splits on
    // the first `:`. A sha-256 hex digest never contains one; refusing here means
    // a custom id that does cannot silently corrupt that split - `gc` would
    // otherwise srem a truncated id from the wrong identity's set.
    if (s.id.includes(':')) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `RedisSessionStore.create requires a session.id without ':' (got ${s.id})`,
      })
    }
    const ttl = this._ttlFor(s)
    // Index BEFORE the record. A record the index does not name authenticates
    // fine but survives `deleteAllForIdentity` forever - a session that outlives
    // the password change or ban that was supposed to end it. A dangling index
    // entry is the far cheaper failure: it is compensated below, and a crash
    // that skips even that leaves an entry `listByIdentity` reads past and the
    // index key's own TTL eventually takes. This is also why `listByIdentity`
    // no longer prunes - see the note there.
    let indexed = 0
    let stored: 'OK' | null
    try {
      if (s.identityId) {
        indexed = await this._redis.sadd(this._idxKey(s.identityId), s.id)
        // Bounded here rather than after the record write, so a crash in between
        // cannot leave an index key with no expiry of its own.
        await this._redis.expire(this._idxKey(s.identityId), this._maxTtlSec)
      }
      // `nx`, because a session id is a primary key. Every SQL dialect raises a
      // unique violation on a duplicate insert; a plain `SET` overwrote the
      // existing session and returned as though it had created one, so a caller
      // that reused an id silently destroyed a live session instead of hearing
      // about the collision.
      stored = await this._redis.set(this._sessKey(s.id), JSON.stringify(s), { ex: ttl, nx: true })
    } catch (err) {
      await this._unindex(s.identityId, s.id, indexed)
      throw err
    }
    if (stored === null) {
      // No compensation on this branch. The id is taken, so the entry names a
      // record that is genuinely there; removing it would unindex somebody
      // else's live session. If the entry was missing before this call, adding
      // it repaired an orphan - keep that too.
      throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${s.id} already exists` })
    }
    // The expiry entry goes in AFTER the record, unlike the identity index.
    // `nx` may have just collided with a live session under this id, and the
    // member is keyed by that id - re-scoring it from a different session's
    // deadlines would move a sweep onto a session that is still valid. Only a
    // create that actually stored gets to schedule one.
    try {
      await this._redis.zadd(this._expKey(), this._expScore(s), this._expMember(s.id, s.identityId))
    } catch (err) {
      // A session nothing will ever sweep is not a session we agreed to store,
      // so unwind the whole create rather than report success. `nx` proved the
      // record is this call's to remove.
      await this._redis.del(this._sessKey(s.id)).catch(() => 0)
      await this._unindex(s.identityId, s.id, indexed)
      throw err
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
    // Reschedule BEFORE the record write. A patch that slides `expiresAt`
    // forward is a renewal, and if the record landed first and this failed, `gc`
    // would still be holding the pre-renewal deadline and would sweep a session
    // that had just been extended. In this order a failure leaves the session
    // scheduled later than the record justifies, which costs one late sweep -
    // and readers reject a stale row regardless.
    await this._redis.zadd(this._expKey(), this._expScore(next), this._expMember(current.id, next.identityId))
    await this._redis.set(this._sessKey(id), JSON.stringify(next), { ex: ttl })
    // A patch that repoints the session at another identity has to move it
    // between the indexes too. Leaving it in the old set made the session
    // invisible to `listByIdentity` for its new owner and, worse, unreachable by
    // `deleteAllForIdentity` - a "sign out everywhere" that could not reach it.
    // The expiry member carries the identity as well, so it moves with them.
    if (current.identityId !== next.identityId) {
      await this._redis.zrem(this._expKey(), this._expMember(current.id, current.identityId))
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
    const session = raw ? parseStoredSession(raw, id) : null
    await this._redis.del(this._sessKey(id))
    if (session?.identityId) {
      await this._redis.srem(this._idxKey(session.identityId), id)
    }
    // The expiry member is keyed by identity too, so a row we could not read
    // leaves an entry only `gc` can retire. That entry names a record that is
    // already gone, so the sweep it triggers is a `del` and an `srem` on nothing.
    await this._redis.zrem(this._expKey(), this._expMember(id, session?.identityId ?? null))
  }

  async listByIdentity(identityId: string): Promise<Sessions.Me[]> {
    const ids = await this._redis.smembers(this._idxKey(identityId))
    if (ids.length === 0) return []
    // Concurrent, not sequential. This backs the active-devices request and runs
    // inside `revokeAllForIdentity`, so N sequential round-trips are N latencies
    // a user waits through.
    const rows = await Promise.all(
      ids.map(async (id): Promise<Sessions.Me | null> => {
        const raw = await this._redis.get(this._sessKey(id))
        // No `srem` here. A missing record may be a `create` between its index
        // write and its record write, and pruning the entry would orphan the
        // session it is about to store - nothing else names it yet, not even
        // the expiry index. Retiring entries is `gc`'s job, and it does that on
        // the session's own deadline rather than on one absent read.
        if (!raw) return null
        // A corrupted row is skipped, not returned: the caller treats it as
        // absent and the next write replaces it.
        return parseStoredSession(raw, id)
      }),
    )
    return rows.filter((row): row is Sessions.Me => row !== null)
  }

  async deleteAllForIdentity(identityId: string): Promise<void> {
    const ids = await this._redis.smembers(this._idxKey(identityId))
    if (ids.length > 0) {
      await this._redis.del(...ids.map((id) => this._sessKey(id)))
      // Every member is known exactly here - the identity is the one we were
      // handed - so none of these rows has to wait for its deadline to leave the
      // expiry index.
      await this._redis.zrem(this._expKey(), ...ids.map((id) => this._expMember(id, identityId)))
    }
    await this._redis.del(this._idxKey(identityId))
  }

  /**
   * Purge every session whose deadline has passed, and clear it out of the
   * indexes on the way. The record's key TTL is derived from
   * `absoluteExpiresAt` alone, so without this sweep nothing at the storage
   * layer ever enforces the sliding `expiresAt`.
   *
   * Driven by the `{prefix}:exp` ZSet, which is scored by whichever of the two
   * deadlines comes first, so the run costs one range query per page plus the
   * rows it actually removes - not a walk of every session that exists. The
   * member carries the owning identity, so a row is removed from its identity
   * index without reading its body at all.
   *
   * Guest sessions are swept here like any other. They sit in no identity index,
   * so the index walk this replaced could never reach them and their expiry was
   * TTL-only.
   *
   * `deleted` counts the members this run removed. `zrem` reports what it
   * actually took, so a row swept concurrently by another instance is counted
   * once, by whichever run won.
   *
   * Serialised across the fleet by a `{prefix}:gc:lease` taken with SET NX, the
   * lease the `Sessions.Store` contract has always promised. An instance that
   * does not get it returns immediately rather than sweeping alongside the
   * holder.
   *
   * NOTE: the lease is not extended mid-sweep. A run that outlasts `gcLeaseSec`
   * loses it, and another instance may start sweeping alongside it. That is
   * tolerated rather than prevented: `del`, `srem` and `zrem` on the same rows
   * are no-ops the second time. On a keyspace big enough for a sweep to outrun
   * the default, raise `gcLeaseSec` rather than reaching for a watchdog: a
   * refresh is only safe if it can prove it still holds the lease, which needs
   * `eval`, which is optional on `RedisLike.Client`.
   */
  async gc(now: number): Promise<{ deleted: number }> {
    const acquired = await this._redis.set(this._leaseKey(), '1', { ex: this._gcLeaseSec, nx: true })
    if (acquired === null) return { deleted: 0 }
    // The lease is never released, only left to expire. Releasing it in a
    // `finally` is the classic unsafe unlock: a sweep that outruns `gcLeaseSec`
    // has already lost the lease to another instance, and deleting it then frees
    // a lease this run no longer owns. A compare-and-delete would need a fencing
    // token and therefore `eval`, which is optional on `RedisLike.Client`.
    // Waiting out the key costs one skipped cycle and removes the failure mode.
    let deleted = 0
    for (;;) {
      // Only what is already due, oldest first. A session still in flight - one
      // whose record write has not landed yet - has a future score or no member
      // at all, so this cannot see it, let alone prune it. That is the whole
      // reason the index walk needed a second confirming read and this does not.
      const due = await this._redis.zrangebyscore(this._expKey(), '-inf', now, {
        limit: { count: GC_PAGE, offset: 0 },
      })
      if (due.length === 0) break
      await Promise.all(
        due.map(async (member) => {
          const { sessionId, identityId } = this._parseExpMember(member)
          await this._redis.del(this._sessKey(sessionId))
          if (identityId) await this._redis.srem(this._idxKey(identityId), sessionId)
        }),
      )
      // Last, so a crash mid-page leaves the members due and the next run
      // repeats the work rather than abandoning a half-cleaned row.
      deleted += await this._redis.zrem(this._expKey(), ...due)
      // A short page means the range is exhausted; anything that became due
      // while this ran belongs to the next cycle.
      if (due.length < GC_PAGE) break
    }
    return { deleted }
  }
}

/** How many expiry members one `gc` page retires. Bounds both the reply size and the fan-out below it. */
const GC_PAGE = 250

/** A plain JSON object - not null, not an array. */
function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function isSessionKind(v: unknown): v is Sessions.Kind {
  return AUTH_SESSION_KINDS.some((kind) => kind === v)
}

function isFactorMethod(v: unknown): v is Sessions.FactorMethod {
  return AUTH_SESSION_FACTOR_METHODS.some((method) => method === v)
}

function isAal(v: unknown): v is Sessions.AAL {
  return v === 1 || v === 2 || v === 3
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
    const parsed: unknown = JSON.parse(raw)
    if (!isRecord(parsed)) return null
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

  const kind = obj.kind
  if (!isSessionKind(kind)) return null

  const aal = obj.aal
  if (!isAal(aal)) return null

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

  // `completedAt` may be an ISO string, since that is what a JSON round-trip
  // makes of a Date.
  //
  // The asymmetry below is deliberate. A *structurally* broken entry - `null`, a
  // primitive, a missing `method` - rejects the whole row, because that is
  // corruption: `Array.isArray` narrows to `any[]`, so the old `.filter` read
  // `.method` off whatever was in there and a single `null` element turned every
  // read of that session into a thrown `TypeError` instead of the `null` this
  // parser exists to return. Every other malformed shape was worse for being
  // quiet: it was dropped, handing back an `aal: 2` session carrying no factors
  // at all, which the step-up logic then reads as authoritative. An *unknown but
  // well-formed* method is the one case that is not corruption - it is what a
  // newer writer adding a factor method produces - so it is skipped instead.
  if (obj.factors !== undefined && !Array.isArray(obj.factors)) return null
  const factorList: unknown[] = Array.isArray(obj.factors) ? obj.factors : []
  // The same 16-element cap `sessions.create` and `parseJwtPayload` apply; this
  // parser was the one door into a session that did not.
  if (factorList.length > 16) return null
  const factors: Sessions.Factor[] = []
  for (const entry of factorList) {
    if (!isRecord(entry)) return null
    if (typeof entry.method !== 'string') return null
    if (!isFactorMethod(entry.method)) continue
    factors.push({ method: entry.method, completedAt: parseStoredDate(entry.completedAt) ?? createdAtDate })
  }

  // A malformed impersonation envelope used to degrade to `actingAs: null`,
  // which reads as an ordinary session belonging to the person being
  // impersonated - the audit trail gone and the window's own expiry cap with it.
  // A present-but-broken envelope fails closed like every field above it.
  let actingAs: Sessions.ActingAs | null = null
  if (obj.actingAs !== undefined && obj.actingAs !== null) {
    const envelope = obj.actingAs
    if (!isRecord(envelope)) return null
    if (typeof envelope.realIdentityId !== 'string' || typeof envelope.reason !== 'string') return null
    const startedAt = parseStoredDate(envelope.startedAt)
    const actingExpiresAt = parseStoredDate(envelope.expiresAt)
    if (!startedAt || !actingExpiresAt) return null
    actingAs = {
      realIdentityId: envelope.realIdentityId,
      reason: envelope.reason,
      startedAt,
      expiresAt: actingExpiresAt,
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
    actingAs,
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
