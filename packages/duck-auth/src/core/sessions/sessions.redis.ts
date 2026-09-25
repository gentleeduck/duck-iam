import type { RedisLike } from '~/core/drivers/redis-like'
import { AuthError } from '~/core/errors'
import { stripUndefined } from '~/core/patch'
import { isFiniteNumber } from '~/core/predicates'
import { assertSessionAllowed } from '~/core/sessions/sessions.constants'
import type { Sessions } from '~/core/sessions/sessions.types'
import { isFactorMethod, isSessionKind } from '~/core/sessions/sessions.types'
import type { TenantContext } from '~/core/tenant/tenant.types'

/** Configuration for the Redis-backed session store. */
export namespace RedisSession {
  export type Cfg<TRedis extends RedisLike.Client = RedisLike.Client> = {
    redis: TRedis
    /**
     * Default `auth`. Final keys:
     *   `${prefix}:sess:{sessionId}`
     *   `${prefix}:idx:identity:{identityId}` (Set of sessionId hashes)
     *   `${prefix}:exp` (ZSet of `sessionId:identityId`, scored by expiry)
     *   `${prefix}:gc:lease`
     */
    prefix?: string
    /** A ceiling on every key TTL; the row's own `absoluteExpiresAt` is authoritative. Default 30 days. */
    maxTtlSec?: number
    /** Default 5 minutes. */
    gcLeaseSec?: number
  }
}

/** Swaps the row only if it is byte-for-byte the one the caller read, so the compare and the write are
 *  one operation. Compares the whole record rather than its `updatedAt` because the reader has the bytes
 *  in hand already and every concurrent write changes them. */
const CAS_SET = `if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
  return 1
end
return 0`

/** No ctx, or one with no `tenantId`, sees every tenant; a named tenant sees only its own rows. */
function inTenant(s: Sessions.Me, ctx: TenantContext | undefined): boolean {
  return ctx?.tenantId === undefined || s.tenantId === ctx.tenantId
}

/** `Sessions.Me.id` is already the sha-256 of the sid, so the primary key and the lookup key are the
 *  same value.
 *
 *  WARN: `update` swaps the record with a Lua compare-and-swap, so a client whose `eval` is missing -
 *  it is optional on {@link RedisLike.Client} - is left with a read, a compare and a separate write.
 *  Two clients can then both read, both pass the compare and both write, and the first write is lost
 *  silently. On a real server that is not a corner: network latency puts both reads before either
 *  write. An operator choosing a client without `eval` is choosing that. */
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

  /** Where the last "revoke everything for this identity" instant is recorded. */
  private _revokedAtKey(identityId: string): string {
    return `${this._prefix}:revokedAt:${identityId}`
  }

  private _leaseKey(): string {
    return `${this._prefix}:gc:lease`
  }

  /** Deployment-wide, scored by the instant a session stops being usable. */
  private _expKey(): string {
    return `${this._prefix}:exp`
  }

  /** One round trip where the client has `MGET`, one per key where it does not. Values come back in
   *  the order asked, so a miss is positional. */
  private _getMany(ids: readonly string[]): Promise<(string | null)[]> {
    if (ids.length === 0) return Promise.resolve([])

    return this._redis.mget
      ? this._redis.mget(...ids.map((id) => this._sessKey(id)))
      : Promise.all(ids.map((id) => this._redis.get(this._sessKey(id))))
  }

  /** The rows behind `ids`, missing and corrupted ones dropped.
   *  WARN: no `srem` for a miss: it may be a `create` between its index write and its record write,
   *  and pruning would orphan it. Retiring entries is `gc`'s job. */
  private async _readMany(ids: readonly string[]): Promise<Sessions.Me[]> {
    const raws = await this._getMany(ids)
    const rows: Sessions.Me[] = []
    ids.forEach((id, i) => {
      const raw = raws[i]
      if (!raw) return
      const row = parseStoredSession(raw, id)
      if (row) rows.push(row)
    })

    return rows
  }

  /** `sessionId:identityId`, so `gc` reaches the owner's index without reading the record. A guest
   *  carries an empty tail, and the split is on the first `:`, which is why `create` refuses an id
   *  holding one. */
  private _expMember(sessionId: string, identityId: string | null): string {
    return `${sessionId}:${identityId ?? ''}`
  }

  /** Inverse of {@link RedisSessionImpl._expMember}. An identity may legitimately contain `:`; a session id may not. */
  private _parseExpMember(member: string): { sessionId: string; identityId: string | null } {
    const cut = member.indexOf(':')
    // Not a member this class wrote. Read as all id and no identity; `del` and `srem` are no-ops on
    // what is not there, so the sweep still clears it.
    if (cut === -1) return { identityId: null, sessionId: member }
    const identityId = member.slice(cut + 1)
    return { identityId: identityId === '' ? null : identityId, sessionId: member.slice(0, cut) }
  }

  /** Whichever deadline comes first: the key TTL tracks `absoluteExpiresAt` alone, so this is all the
   *  enforcement the sliding `expiresAt` gets here. */
  private _expScore(session: Pick<Sessions.Me, 'expiresAt' | 'absoluteExpiresAt'>): number {
    const abs = parseStoredDate(session.absoluteExpiresAt)
    const idle = parseStoredDate(session.expiresAt)
    // A row nothing can date is scored as already due rather than never, so `gc` drops it. The same
    // fail-closed answer `parseStoredSession` gives a reader.
    if (!abs && !idle) return 0
    return Math.min(abs?.getTime() ?? Number.POSITIVE_INFINITY, idle?.getTime() ?? Number.POSITIVE_INFINITY)
  }

  private _ttlFor(session: Pick<Sessions.Me, 'absoluteExpiresAt'>): number {
    // WARN: the read path's parser, not a number cast. A serialised date would make every step below
    // `NaN`, and `{ ex: NaN }` is a key with no expiry on some clients.
    const abs = parseStoredDate(session.absoluteExpiresAt)
    // The cap bounds an unparseable value without destroying a live session the way a 1-second floor
    // would, and `resolveBySid` still refuses the row if it really is stale.
    if (!abs) return this._maxTtlSec
    const remainingSec = Math.ceil(Math.max(0, abs.getTime() - Date.now()) / 1000)
    return Math.max(1, Math.min(this._maxTtlSec, remainingSec))
  }

  /** Undoes the entry a failed `create` added, and only that one: `sadd` reports whether it actually
   *  added, so a collision cannot remove the entry that was there first. */
  private async _unindex(identityId: string | null, sessionId: string, added: number): Promise<void> {
    // Best effort: the record write has already failed, and an entry naming nothing is skipped by
    // every reader and taken by the index key's own TTL.
    await this._redis.zrem(this._expKey(), this._expMember(sessionId, identityId)).catch(() => 0)
    if (!identityId || added === 0) return
    await this._redis.srem(this._idxKey(identityId), sessionId).catch(() => 0)
  }

  /** Writes the session and adds it to its identity's index. */
  async create(s: Sessions.CreateInput): Promise<void> {
    if (!s.id) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'RedisSessionStore.create requires session.id to be set (sha-256 of sid)',
      })
    }
    // A custom id holding `:` would corrupt the expiry member's split, and `gc` would srem the wrong
    // identity's set.
    if (s.id.includes(':')) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `RedisSessionStore.create requires a session.id without ':' (got ${s.id})`,
      })
    }
    // Refused here rather than stored: `parseStoredSession` rejects these, so the row would be written
    // and then read back as a revoked session for the rest of its life.
    assertSessionAllowed(s)
    // SECURITY: a session minted before this identity's last revoke does not survive it, whichever
    // order the two writes land in - otherwise a sign-in already in flight when "sign out everywhere"
    // ran came back alive on the other side of it.
    // `AUTH_STALE_WRITE` and not `AUTH_SESSION_REVOKED`, which is in the reader's absent set and would
    // be read back as "no session": this is a lost race, and whether the sign-in is worth attempting
    // again is only the caller's to decide if the refusal reaches it.
    if (s.identityId) {
      const mark = await this._redis.get(this._revokedAtKey(s.identityId))
      if (mark !== null) {
        const revokedAt = Number(mark)
        // A guard that cannot read its own token refuses rather than waving the write through.
        if (!Number.isFinite(revokedAt)) {
          throw new AuthError('AUTH_STALE_WRITE', { expected: s.createdAt.getTime() })
        }
        if (s.createdAt.getTime() < revokedAt) {
          throw new AuthError('AUTH_STALE_WRITE', { actual: revokedAt, expected: s.createdAt.getTime() })
        }
      }
    }
    const ttl = this._ttlFor(s)
    // SECURITY: index BEFORE the record. A record the index does not name survives
    // `deleteAllForIdentity` forever; a dangling entry is compensated below and swept anyway.
    let indexed = 0
    let stored: 'OK' | null
    try {
      if (s.identityId) {
        indexed = await this._redis.sadd(this._idxKey(s.identityId), s.id)
        // Bounded before the record write, so a crash between them cannot leave a key with no expiry.
        await this._redis.expire(this._idxKey(s.identityId), this._maxTtlSec)
      }
      // `nx`, because a session id is a primary key: a plain `SET` would destroy a live session on a
      // reused id instead of reporting the collision every SQL dialect raises.
      stored = await this._redis.set(this._sessKey(s.id), JSON.stringify(s), { ex: ttl, nx: true })
    } catch (err) {
      await this._unindex(s.identityId, s.id, indexed)
      throw err
    }
    if (stored === null) {
      // No compensation here: the id is taken, so the entry names a record that is genuinely there and
      // removing it would unindex somebody else's live session.
      throw new AuthError('AUTH_ALREADY_EXISTS', { detail: `session ${s.id} already exists` })
    }
    // After the record, unlike the identity index: the member is keyed by session id, so re-scoring it
    // after an `nx` collision would move a sweep onto a session that is still valid.
    try {
      await this._redis.zadd(this._expKey(), this._expScore(s), this._expMember(s.id, s.identityId))
    } catch (err) {
      // A session nothing will ever sweep is not one worth storing, and `nx` proved the record is
      // this call's to remove.
      await this._redis.del(this._sessKey(s.id)).catch(() => 0)
      await this._unindex(s.identityId, s.id, indexed)
      throw err
    }
  }

  /** The session under this hashed id, throwing `AUTH_SESSION_REVOKED` when the key is gone. */
  async getByHash(sidHash: string): Promise<Sessions.Me> {
    const raw = await this._redis.get(this._sessKey(sidHash))
    if (!raw) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${sidHash} not found` })
    const row = parseStoredSession(raw, sidHash)
    if (!row) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${sidHash} corrupted` })

    return row
  }

  /** Merges a patch onto the stored session, rewriting it under the remaining TTL. */
  async update(id: string, patch: Partial<Sessions.Me>, expectedUpdatedAt?: Date): Promise<Sessions.Me> {
    for (let attempt = 0; ; attempt++) {
      const raw = await this._redis.get(this._sessKey(id))
      if (!raw) {
        throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })
      }
      const current = parseStoredSession(raw, id)
      if (!current) {
        throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} corrupted` })
      }
      if (expectedUpdatedAt !== undefined && current.updatedAt.getTime() !== expectedUpdatedAt.getTime()) {
        throw new AuthError('AUTH_STALE_WRITE', {
          actual: current.updatedAt.getTime(),
          expected: expectedUpdatedAt.getTime(),
        })
      }
      // `id` is pinned to the key the row lives under, and `undefined` means "leave this alone".
      // `updatedAt` is stamped here rather than taken from the patch, as `$onUpdate` does in SQL, and is
      // strictly increasing: it is the token `expectedUpdatedAt` compares, and `Date` resolves to the
      // millisecond, so two writes inside one would stamp equal and the second land on top of the first.
      const next: Sessions.Me = {
        ...current,
        ...stripUndefined(patch),
        id: current.id,
        updatedAt: new Date(Math.max(Date.now(), current.updatedAt.getTime() + 1)),
      }
      assertSessionAllowed(next)
      const ttl = this._ttlFor(next)
      // Reschedule BEFORE the record write: the other order lets `gc` sweep a session a renewal had just
      // extended. A swap that then loses leaves the member rescheduled for a write that never landed,
      // which costs at worst one wasted sweep or one early retirement of a row the reader would have
      // taken - wrong in the safe direction, either way.
      await this._redis.zadd(this._expKey(), this._expScore(next), this._expMember(current.id, next.identityId))
      // SECURITY: compare-and-swap on the exact bytes read. The guard above is a compare and a write with
      // a gap between them, so two clients can both read the same row, both find their expectation
      // intact and both write - and the first write is lost with nothing raised. The script makes the
      // compare and the write one operation; without `eval` on the client it is the gap it always was,
      // which the class doc says out loud.
      let swapped = true
      if (this._redis.eval) {
        const won = await this._redis.eval(CAS_SET, [this._sessKey(id)], [raw, JSON.stringify(next), String(ttl)])
        swapped = Number(won) === 1
      } else {
        await this._redis.set(this._sessKey(id), JSON.stringify(next), { ex: ttl })
      }
      if (!swapped) {
        // An unguarded patch means "apply this to whatever is current", so losing the swap is a reason to
        // re-read and apply it to the row that won rather than to fail. A guarded one already named the
        // row it meant, and that row is gone.
        if (expectedUpdatedAt === undefined && attempt < 2) continue
        throw new AuthError('AUTH_STALE_WRITE', {
          expected: expectedUpdatedAt?.getTime() ?? current.updatedAt.getTime(),
        })
      }
      // SECURITY: a repointed session moves between the indexes, or "sign out everywhere" cannot reach
      // it under its new owner. The expiry member carries the identity, so it moves too.
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
  }

  /** Removes the session and takes it out of its identity's index. */
  async delete(id: string): Promise<void> {
    const raw = await this._redis.get(this._sessKey(id))
    const session = raw ? parseStoredSession(raw, id) : null
    await this._redis.del(this._sessKey(id))
    if (session?.identityId) {
      await this._redis.srem(this._idxKey(session.identityId), id)
    }
    // The expiry member is keyed by identity too, so an unreadable row leaves an entry only `gc` can
    // retire, naming a record already gone.
    await this._redis.zrem(this._expKey(), this._expMember(id, session?.identityId ?? null))
  }

  /** Every live session for this identity, dropping index entries whose row has expired. */
  async listByIdentity(identityId: string, ctx?: TenantContext): Promise<Sessions.Me[]> {
    const ids = await this._redis.smembers(this._idxKey(identityId))
    // The index is keyed by identity, not identity+tenant, so the filter falls on the rows rather than
    // the read. A tenant asking for its device list must not see the same person in another tenant.
    return (await this._readMany(ids)).filter((row) => inTenant(row, ctx))
  }

  /** Removes every session for this identity, and the index itself. */
  async deleteAllForIdentity(identityId: string, ctx?: TenantContext): Promise<void> {
    // Written before the index is read, so a `create` landing after the sweep is refused by `create`'s
    // own check rather than surviving. The TTL is the longest a session can live, past which nothing
    // minted before the mark could still be valid.
    // Set on the scoped path too. The mark is identity-wide, so a scoped revoke also refuses a racing
    // create for the identity's other tenants; that costs the retry `AUTH_STALE_WRITE` asks for, where
    // a key per tenant would refuse nothing extra but could not be told apart from an identity whose
    // id happens to contain the separator.
    await this._redis.set(this._revokedAtKey(identityId), String(Date.now()), { ex: this._maxTtlSec })
    const ids = await this._redis.smembers(this._idxKey(identityId))
    if (ids.length === 0) return
    // Unscoped, every row goes and nothing has to be read.
    if (ctx?.tenantId === undefined) {
      await this._redis.del(...ids.map((id) => this._sessKey(id)))
      // Every member is known exactly, so no row has to wait for its deadline to leave the index.
      await this._redis.zrem(this._expKey(), ...ids.map((id) => this._expMember(id, identityId)))
      // SECURITY: `srem` of the members just read, never `del` of the key. A `create` that indexed
      // itself after `smembers` is not in `ids`, and dropping the whole key took its entry with it -
      // leaving a live session no later revoke could find. Redis retires an empty set key itself.
      await this._redis.srem(this._idxKey(identityId), ...ids)
      return
    }
    // Scoped, membership is per row, so each is read first. An unreadable one is left alone rather than
    // swept: it may be a `create` mid-flight, and its tenant is exactly what cannot be established.
    const doomed: string[] = []
    for (const id of ids) {
      const raw = await this._redis.get(this._sessKey(id))
      if (!raw) continue
      const row = parseStoredSession(raw, id)
      if (row && inTenant(row, ctx)) doomed.push(id)
    }
    if (doomed.length === 0) return
    await this._redis.del(...doomed.map((id) => this._sessKey(id)))
    await this._redis.zrem(this._expKey(), ...doomed.map((id) => this._expMember(id, identityId)))
    // `srem`, never `del`: the identity's other tenants still have live sessions under this key, and
    // dropping it would leave them alive and impossible to sign out.
    await this._redis.srem(this._idxKey(identityId), ...doomed)
  }

  /** Unscoped by tenant, like the rest of the set-based forms. */
  async deleteAllForIdentities(identityIds: string[]): Promise<Sessions.Revoked[]> {
    if (identityIds.length === 0) return []
    const mark = String(Date.now())
    await Promise.all(
      identityIds.map((identityId) => this._redis.set(this._revokedAtKey(identityId), mark, { ex: this._maxTtlSec })),
    )
    const found = await Promise.all(
      identityIds.map(async (identityId) => ({
        identityId,
        ids: await this._redis.smembers(this._idxKey(identityId)),
      })),
    )
    const live = found.filter((f) => f.ids.length > 0)
    if (live.length > 0) {
      await this._redis.del(...live.flatMap((f) => f.ids.map((id) => this._sessKey(id))))
      await this._redis.zrem(
        this._expKey(),
        ...live.flatMap((f) => f.ids.map((id) => this._expMember(id, f.identityId))),
      )
    }
    // `srem` of the members just read, never `del` of the key - see `deleteAllForIdentity`. Identities
    // with nothing indexed are skipped rather than emptied, which is the same thing and one less call.
    await Promise.all(live.map((f) => this._redis.srem(this._idxKey(f.identityId), ...f.ids)))

    // Keyed off the index rather than the records: a record that no longer parses was still revoked.
    return live.flatMap((f) => f.ids.map((id) => ({ id, identityId: f.identityId })))
  }

  /** The records are read first because the index entry and the expiry member are both keyed by the
   *  owning identity, which only the record names. */
  async deleteMany(ids: string[]): Promise<Sessions.Revoked[]> {
    if (ids.length === 0) return []
    const raws = await this._getMany(ids)
    // Presence is the key existing, not the row parsing: a corrupted record is still a record, and
    // leaving it behind would make `deleteMany` the one delete that cannot clear one.
    const present: { id: string; identityId: string | null }[] = []
    ids.forEach((id, i) => {
      const raw = raws[i]
      if (!raw) return
      present.push({ id, identityId: parseStoredSession(raw, id)?.identityId ?? null })
    })
    if (present.length === 0) return []

    await this._redis.del(...present.map((p) => this._sessKey(p.id)))
    await this._redis.zrem(this._expKey(), ...present.map((p) => this._expMember(p.id, p.identityId)))
    const byIdentity = new Map<string, string[]>()
    for (const p of present) {
      if (p.identityId === null) continue
      const ids = byIdentity.get(p.identityId)
      if (ids) ids.push(p.id)
      else byIdentity.set(p.identityId, [p.id])
    }
    await Promise.all([...byIdentity].map(([identityId, sids]) => this._redis.srem(this._idxKey(identityId), ...sids)))

    return present
  }

  /**
   * Driven by the `{prefix}:exp` ZSet, one range query per page. `deleted` counts what `zrem` took, so a
   * row swept concurrently is counted once. Serialised by a `{prefix}:gc:lease` taken with SET NX; an
   * instance that misses it returns immediately.
   *
   * NOTE: the lease is not extended mid-sweep, so a run outlasting `gcLeaseSec` may be joined by
   * another instance. Tolerated, since `del`, `srem` and `zrem` are no-ops the second time.
   */
  async gc(now: number): Promise<{ deleted: number }> {
    // The cutoff is the caller's, and every comparison against NaN is false while every one against
    // Infinity is true, so an unusable number does not fail - it sweeps nothing or it sweeps everything,
    // and the dialects disagreed about which.
    if (!isFiniteNumber(now)) {
      throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'gc(now) requires a finite epoch-ms cutoff' })
    }
    const acquired = await this._redis.set(this._leaseKey(), '1', { ex: this._gcLeaseSec, nx: true })
    if (acquired === null) return { deleted: 0 }
    // WARN: the lease is left to expire, never released. Releasing it in a `finally` is the unsafe
    // unlock: a sweep that outran `gcLeaseSec` would free a lease another instance now holds.
    let deleted = 0
    for (;;) {
      // Only what is already due, oldest first. A session still in flight has a future score or no
      // member at all, which is why this needs no confirming read where the index walk does.
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
      // Last, so a crash mid-page leaves the members due and the next run repeats rather than abandons.
      deleted += await this._redis.zrem(this._expKey(), ...due)
      // A short page exhausts the range; anything that came due while this ran is the next cycle's.
      if (due.length < GC_PAGE) break
    }
    return { deleted }
  }
}

/** Bounds both the `zrangebyscore` reply and the fan-out under it. */
const GC_PAGE = 250

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function isAal(v: unknown): v is Sessions.AAL {
  return v === 1 || v === 2 || v === 3
}

function parseStoredDate(v: unknown): Date | null {
  if (v instanceof Date) return v
  if (typeof v === 'string') {
    const d = new Date(v)
    return Number.isFinite(d.getTime()) ? d : null
  }
  if (typeof v === 'number' && Number.isFinite(v)) return new Date(v)
  return null
}

/** `expectedId` is the key the row was read under. Every field below fails closed, and so does the
 *  row's agreement with its own key. */
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
  // Callers revoke by the body's `id`, but the row lives under the key. On a disagreement, acting on
  // the row deletes some other key and leaves this one live, surviving its own revocation.
  if (id !== expectedId) return null

  // `identityId` decides whose session this is. Coercing a non-string to `null` makes an authenticated
  // session a guest one: it belongs to nobody and `deleteAllForIdentity` cannot reach it.
  if (obj.identityId !== undefined && obj.identityId !== null && typeof obj.identityId !== 'string') return null

  // The same mistake with the opposite blast radius: a caller skips the check when `csrfHash` is
  // `null`, so coercing a corrupt value there switches CSRF protection off rather than degrading it.
  if (obj.csrfHash !== undefined && obj.csrfHash !== null && typeof obj.csrfHash !== 'string') return null

  const kind = obj.kind
  if (!isSessionKind(kind)) return null

  const aal = obj.aal
  if (!isAal(aal)) return null

  const expiresAtDate = parseStoredDate(obj.expiresAt)
  if (!expiresAtDate) return null
  const absoluteExpiresAtDate = parseStoredDate(obj.absoluteExpiresAt)
  if (!absoluteExpiresAtDate) return null
  const createdAtDate = parseStoredDate(obj.createdAt)
  if (!createdAtDate) return null
  // SECURITY: rejected rather than defaulted. The freshness gate measures against `rotatedAt`, so a
  // row falling back to any later date would read as permanently fresh.
  const rotatedAtDate = parseStoredDate(obj.rotatedAt)
  if (!rotatedAtDate) return null

  // WARN: the asymmetry is deliberate. A structurally broken entry rejects the whole row, since
  // dropping it hands back an `aal: 2` session with no factors that step-up reads as authoritative.
  // An unknown but well-formed method is what a newer writer produces, so it is skipped.
  if (obj.factors !== undefined && !Array.isArray(obj.factors)) return null
  const factorList: unknown[] = Array.isArray(obj.factors) ? obj.factors : []
  // The same 16-element cap `sessions.create` applies.
  if (factorList.length > 16) return null
  const factors: Sessions.Factor[] = []
  for (const entry of factorList) {
    if (!isRecord(entry)) return null
    if (typeof entry.method !== 'string') return null
    if (!isFactorMethod(entry.method)) continue
    factors.push({ method: entry.method, completedAt: parseStoredDate(entry.completedAt) ?? createdAtDate })
  }

  // A present-but-broken envelope fails closed like every field above. Degrading it to `null` reads as
  // an ordinary session belonging to the person being impersonated, audit trail and expiry cap gone.
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
    // Falls back rather than refusing: a row written before `updatedAt` existed is a live session, and
    // rejecting it here would sign every one of them out on deploy.
    updatedAt: parseStoredDate(obj.updatedAt) ?? createdAtDate,
    rotatedAt: rotatedAtDate,
    expiresAt: expiresAtDate,
    absoluteExpiresAt: absoluteExpiresAtDate,
    actingAs,
  }
  return session
}

/** Constructs a {@link RedisSessionImpl} session store. */
export function session<TRedis extends RedisLike.Client = RedisLike.Client>(
  cfg: RedisSession.Cfg<TRedis>,
): RedisSessionImpl<TRedis> {
  return new RedisSessionImpl(cfg)
}

/** {@link session} under its longer name. */
export function redisSessionImpl(...args: ConstructorParameters<typeof RedisSessionImpl>): RedisSessionImpl {
  return new RedisSessionImpl(...args)
}
