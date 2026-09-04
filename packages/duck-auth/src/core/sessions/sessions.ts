import { BATCH_NOT_FOUND, type Batch, batchResult, loopFallback } from '~/core/batch'
import type { Events } from '~/core/events/events.types'
import { isExpiredAt, isFiniteNumber } from '../credentials/credentials'
import { randomToken, sha256 } from '../crypto'
import { AuthError } from '../errors'
import type { Identities } from '../identities/identities.types'
import type { TenantContext } from '../tenant/tenant.types'
import { DEFAULT_SESSION_CONFIG, SESSION_COLUMN_CAPS } from './sessions.constants'
import { AUTH_SESSION_FACTOR_METHODS, type Sessions } from './sessions.types'

/**
 * Sessions facet - the only path that creates / rotates / revokes sessions.
 * Every privilege-changing transition routes through {@link rotateOrCreate}
 * so the session-fixation discipline lives in exactly one place.
 *
 * Resolution is on `AuthEngine.resolveSession()` rather than here because the
 * Transport contract drives extraction; this facet owns lifecycle only.
 */
export class SessionsImpl {
  private readonly _cfg: Sessions.Cfg

  constructor(
    private readonly _store: Sessions.Store,
    private readonly _events: Events.IBus,
    private readonly cfg?: Partial<Sessions.Cfg>,
  ) {
    this._cfg = {
      ttlMs: this.cfg?.ttlMs ?? DEFAULT_SESSION_CONFIG.ttlMs,
      absoluteTtlMs: this.cfg?.absoluteTtlMs ?? DEFAULT_SESSION_CONFIG.absoluteTtlMs,
      freshnessMs: this.cfg?.freshnessMs ?? DEFAULT_SESSION_CONFIG.freshnessMs,
    }
  }

  /**
   * Build a fresh session record + persist it.
   *
   * Returns `{ session, sid }` where `session.id` is the **hashed** row key
   * (used internally + as the audit-log identifier) and `sid` is the
   * **plaintext** session identifier - the value the caller passes to
   * `Transport.issue()` to put on the wire. The plaintext sid never appears
   * on the persisted row; only its sha-256 hash does.
   */
  async create(input: Sessions.MintInput): Promise<{ session: Sessions.Me; sid: string; csrfToken: string }> {
    // Cap factors length so a buggy caller can't bloat the session row's
    // JSON column. Real flows mint sessions with 1-3 factors.
    if (!Array.isArray(input.factors) || input.factors.length > 16) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'sessions.create: factors must be an array <=16',
      })
    }
    // Contents too, not just the array shape: the Redis reader drops unlisted methods and
    // non-Date `completedAt`, so this would persist a row that can't be read back intact.
    for (const f of input.factors) {
      if (
        typeof f !== 'object' ||
        f === null ||
        !AUTH_SESSION_FACTOR_METHODS.includes((f as Sessions.Factor).method) ||
        !((f as Sessions.Factor).completedAt instanceof Date)
      ) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: 'sessions.create: each factor must be { method: FactorMethod, completedAt: Date }',
        })
      }
    }
    const sid = randomToken(32)
    // Mint plaintext for the cookie, store only the hash on the row.
    const csrfToken = randomToken(32)
    const now = Date.now()
    const nowDate = new Date(now)
    const session: Sessions.Me = {
      id: sha256(sid),
      identityId: input.identityId,
      kind: input.kind,
      aal: input.aal,
      factors: input.factors,
      tenantId: input.tenantId ?? null,
      // Persist truncated ip/UA/fingerprint so a hostile header cannot bloat the session row.
      ip: typeof input.ip === 'string' && input.ip.length > 0 ? input.ip.slice(0, SESSION_COLUMN_CAPS.ip) : null,
      userAgent:
        typeof input.userAgent === 'string' && input.userAgent.length > 0
          ? input.userAgent.slice(0, SESSION_COLUMN_CAPS.userAgent)
          : null,
      fingerprint:
        typeof input.fingerprint === 'string' && input.fingerprint.length > 0
          ? input.fingerprint.slice(0, SESSION_COLUMN_CAPS.fingerprint)
          : null,
      actingAs: input.actingAs ?? null,
      csrfHash: sha256(csrfToken),
      createdAt: nowDate,
      rotatedAt: nowDate,
      expiresAt: new Date(now + this._cfg.ttlMs),
      absoluteExpiresAt: new Date(now + this._cfg.absoluteTtlMs),
      fresh: true,
    }

    await this._store.create(session)
    await this._events.emit('session.created', { session, identity: input.identity ?? null })
    return { session, sid, csrfToken }
  }

  /**
   * DESIGN section 37 rotation matrix. Single code path for every transition that
   * changes a session's identity, AAL, or privilege. The library asserts that
   * flow handlers always route through this method so fixation is structurally
   * impossible to forget.
   */
  async rotateOrCreate(input: Sessions.RotateInput): Promise<{ session: Sessions.Me; sid: string; csrfToken: string }> {
    if (input.purpose === 'credential-change') {
      if (input.identityId) {
        const identityId = input.identityId
        const doomed = await this._store.listByIdentity(identityId)
        await this._store.deleteAllForIdentity(identityId)
        await Promise.all(doomed.map((s) => this._events.emit('session.revoked', { sessionId: s.id, identityId })))
      }
      // A guest credential-change has no identity to sweep; it still mints + rotates.
      const fresh = await this.create(input)
      await this._events.emit('session.rotated', {
        session: fresh.session,
        ...(input.previousSid !== undefined && { previousSessionId: sha256(input.previousSid) }),
      })
      return fresh
    }

    const fresh = await this.create(input)
    if (
      input.previousSid !== undefined &&
      typeof input.previousSid === 'string' &&
      input.previousSid.length > 0 &&
      input.previousSid.length <= 4096
    ) {
      const prevHash = sha256(input.previousSid)
      switch (input.purpose) {
        case 'signin':
        case 're-auth':
        case 'guest-promotion':
        case 'sign-up':
        case 'step-down':
        case 'impersonate-release':
          await this._store.delete(prevHash)
          await this._events.emit('session.revoked', {
            sessionId: prevHash,
            identityId: input.identityId,
          })
          break
        case 'step-up': {
          // Old SID is downgraded, not deleted, so long-lived tabs keep working, but at
          // the prior AAL with fresh=false. Re-step-up is required for privileged ops.
          const prev = await this._store.getByHash(prevHash)
          if (prev) {
            await this._store.update(prev.id, { aal: prev.aal, fresh: false })
          }
          break
        }
        case 'impersonate-start':
          // Real session is preserved alongside the new actingAs session; no revoke.
          break
        default: {
          // Compile-time exhaustiveness: adding a purpose without deciding its revocation
          // semantics is a build error, not a silent no-op.
          const _exhaustive: never = input.purpose
          throw new AuthError('AUTH_MISCONFIGURED', {
            detail: `sessions.rotateOrCreate: unhandled purpose '${String(_exhaustive)}'`,
          })
        }
      }
      await this._events.emit('session.rotated', {
        session: fresh.session,
        previousSessionId: prevHash,
      })
      return fresh
    }
    await this._events.emit('session.rotated', { session: fresh.session })
    return fresh
  }

  /**
   * Revoke a single session by plaintext SID. Answers with the session that was
   * revoked - `null` when the SID matched nothing - so a caller can say whose
   * device just went, and tell a real revocation from a no-op. The row is
   * already read to find it; returning it costs nothing.
   */
  async revoke(sid: string): Promise<Sessions.Me | null> {
    if (typeof sid !== 'string' || sid.length === 0 || sid.length > 4096) return null
    const hash = sha256(sid)
    const s = await this._store.getByHash(hash)
    if (!s) return null
    await this._store.delete(s.id)
    await this._events.emit('session.revoked', {
      sessionId: s.id,
      identityId: s.identityId,
    })
    return s
  }

  /**
   * Revoke by session id (the stored hash). Use when you have ISession.id but
   * not the plaintext SID. See {@link revoke} for the return.
   */
  async revokeByHash(sessionId: string): Promise<Sessions.Me | null> {
    const s = await this._store.getByHash(sessionId)
    if (!s) return null
    await this._store.delete(s.id)
    await this._events.emit('session.revoked', { sessionId: s.id, identityId: s.identityId })
    return s
  }

  /**
   * Revoke every session belonging to an identity (used by credential-change
   * paths). Answers with the sessions that were revoked - the list is already
   * read to emit one event per session, so "you were signed out of 4 devices"
   * needs no second query, and an empty array says there was nothing to end.
   */
  async revokeAllForIdentity(identityId: string, ctx?: TenantContext): Promise<Sessions.Me[]> {
    const all = await this._store.listByIdentity(identityId, ctx)
    await this._store.deleteAllForIdentity(identityId, ctx)
    await Promise.all(all.map((s) => this._events.emit('session.revoked', { sessionId: s.id, identityId })))
    return all
  }

  /**
   * Resolve a plaintext SID to its session row (no identity join), refusing one
   * that is past either deadline.
   *
   * The gate is here and not in the store on purpose: `getByHash` means "the row
   * filed under this key", and whether a session is still usable is policy. But
   * every caller of this method gates something privileged on the answer -
   * completing a step-up, starting an impersonation, the MFA re-check on a
   * password reset - and two of them hand the result straight to
   * `rotateOrCreate`, which mints a new live session from it. Without the gate,
   * presenting an expired sid to any of them resurrected it. This method reads
   * like `resolveBySid` and was the only one of the two that did not check.
   *
   * `fresh` is recomputed from `rotatedAt` rather than read off the row. Only
   * `touch` ever refreshed the stored flag, so a session written `fresh: true`
   * and never touched still claimed freshness weeks later - and the
   * password-reset gate reads exactly that field.
   */
  async getBySid(sid: string): Promise<Sessions.Me | null> {
    // Defensive typeof + length cap; authSha256(non-string) throws + multi-MB
    // input bloats hashing.
    if (typeof sid !== 'string' || sid.length === 0 || sid.length > 4096) return null
    const session = await this._store.getByHash(sha256(sid))
    if (!session) return null
    const now = Date.now()
    if (isSessionExpired(session, now)) {
      // The same side effect `resolveBySid` has: a row nobody can use should not
      // sit there waiting for `gc` to come round to it.
      await this._store.delete(session.id)
      return null
    }
    return { ...session, fresh: isSessionFresh(session, now, this._cfg.freshnessMs) }
  }

  /** Refresh expiresAt by ttlMs without rotating the SID. Stops fresh-window slip. */
  async touch(sid: string): Promise<Sessions.Me | null> {
    if (typeof sid !== 'string' || sid.length === 0 || sid.length > 4096) return null
    const hash = sha256(sid)
    const s = await this._store.getByHash(hash)
    if (!s) return null
    const now = Date.now()
    // Fail closed on either deadline, so `touch` cannot revive a session
    // `resolveBySid` would have rejected.
    if (isSessionExpired(s, now)) {
      await this._store.delete(s.id)
      return null
    }
    // Finite: the guard above rejected everything else, so the cap below is a
    // real number and never `NaN`.
    const absoluteExpiresAtMs = deadlineMs(s.absoluteExpiresAt)
    const newExpiresAt = new Date(Math.min(absoluteExpiresAtMs, now + this._cfg.ttlMs))
    return this._store.update(s.id, { expiresAt: newExpiresAt, fresh: isSessionFresh(s, now, this._cfg.freshnessMs) })
  }

  /**
   * List all live sessions for an identity. Used by UI's "active devices view.
   *
   * Pass a `ctx` in a multi-tenant deployment. Identities are global, so an
   * unscoped call is a cross-tenant read: tenant A's device list showing the
   * same person's tenant B sessions, IP and user-agent included.
   */
  async listForIdentity(identityId: string, ctx?: TenantContext): Promise<Sessions.Me[]> {
    return this._store.listByIdentity(identityId, ctx)
  }

  /** Periodic GC. Caller schedules under leader-lock for distributed deployments. */
  async gc(): Promise<{ deleted: number }> {
    return this._store.gc(Date.now())
  }

  /** Create a guest session - no identity, AAL=1, kind='guest'. Promotable on signin. */
  async createGuest(
    opts: { tenantId?: string; ip?: string; userAgent?: string } = {},
  ): Promise<{ session: Sessions.Me; sid: string; csrfToken: string }> {
    return this.create({
      identityId: null,
      kind: 'guest',
      aal: 1,
      factors: [],
      tenantId: opts.tenantId ?? null,
      ip: opts.ip ?? null,
      userAgent: opts.userAgent ?? null,
    })
  }

  /** Promote a guest session to an authed session. SID rotates; carts/drafts move by identity. */
  async promoteGuest(input: {
    guestSid: string
    identityId: string
    factors: Sessions.Factor[]
    aal: Sessions.AAL
    tenantId?: string
    ip?: string
    userAgent?: string
    /** Optional {@link Sessions.MintInput.identity} passthrough for callers that already hold the row. */
    identity?: Identities.Me | null
    /** Forwarded to {@link Sessions.MintInput}; guest device-binding survives promotion. */
    fingerprint?: string | null
    actingAs?: Sessions.ActingAs | null
  }): Promise<{ session: Sessions.Me; sid: string; csrfToken: string }> {
    return this.rotateOrCreate({
      purpose: 'guest-promotion',
      previousSid: input.guestSid,
      identityId: input.identityId,
      identity: input.identity ?? null,
      kind: 'user',
      aal: input.aal,
      factors: input.factors,
      tenantId: input.tenantId ?? null,
      ip: input.ip ?? null,
      userAgent: input.userAgent ?? null,
      fingerprint: input.fingerprint ?? null,
      actingAs: input.actingAs ?? null,
    })
  }

  // --- batch ----------------------------------------------------------

  /**
   * Revokes every session for each of `identityIds`. One statement when the
   * store supports it, otherwise one sweep per identity.
   *
   * Emits one `session.revoked` per session actually removed - an identity that
   * had no sessions emits nothing and reports `not-found`, so a caller cannot
   * mistake "swept clean" for "there was something to sweep".
   */
  async revokeAllForIdentities(identityIds: readonly string[]): Promise<Batch.Result> {
    if (identityIds.length === 0) return batchResult([])

    // Read the doomed rows first: after the delete there is nothing left to
    // name in the events.
    const doomed = this._store.listByIdentities
      ? await this._store.listByIdentities(identityIds)
      : (await Promise.all(identityIds.map((id) => this._store.listByIdentity(id)))).flat()

    const result = this._store.deleteAllForIdentities
      ? await this._store.deleteAllForIdentities(identityIds)
      : await loopFallback(identityIds, async (id) => {
          if (!doomed.some((s) => s.identityId === id)) return BATCH_NOT_FOUND
          await this._store.deleteAllForIdentity(id)
        })

    const revoked = new Set(result.outcomes.filter((o) => o.ok).map((o) => o.id))
    for (const s of doomed) {
      if (s.identityId !== null && revoked.has(s.identityId)) {
        await this._events.emit('session.revoked', { identityId: s.identityId, sessionId: s.id })
      }
    }
    return result
  }

  /** Revokes sessions by their hashed ids. Emits one `session.revoked` per row removed. */
  async revokeByHashes(ids: readonly string[]): Promise<Batch.Result> {
    if (ids.length === 0) return batchResult([])
    const rows = await Promise.all(ids.map((id) => this._store.getByHash(id)))
    const result = this._store.deleteMany
      ? await this._store.deleteMany(ids)
      : await loopFallback(ids, async (id) => {
          if (!rows.some((r) => r?.id === id)) return BATCH_NOT_FOUND
          await this._store.delete(id)
        })
    for (const [i, outcome] of result.outcomes.entries()) {
      if (outcome.ok) {
        await this._events.emit('session.revoked', {
          identityId: rows[i]?.identityId ?? null,
          sessionId: ids[i] ?? outcome.id,
        })
      }
    }
    return result
  }
}

/** A deadline as epoch ms, or `NaN` when the value is not a readable one. */
function deadlineMs(v: unknown): number {
  if (v instanceof Date) return v.getTime()
  return isFiniteNumber(v) ? v : Number.NaN
}

/**
 * True when a **required** deadline has passed, or cannot be read at all.
 *
 * `isExpiredAt` cannot stand in here: it reads a missing value as "no deadline,
 * never expires". That is right for an optional impersonation window and exactly
 * backwards for a deadline every session is required to carry. Failing closed
 * matters because `NaN < now` is false, so a lenient read keeps a should-be-dead
 * session alive forever - and only an adapter bug produces one, which is the
 * case least worth trusting.
 */
function isDeadlinePast(v: unknown, now: number): boolean {
  const ms = deadlineMs(v)
  return !Number.isFinite(ms) || ms < now
}

/** Past either deadline: the sliding idle timeout, or the hard absolute cap. */
export function isSessionExpired(session: Pick<Sessions.Me, 'expiresAt' | 'absoluteExpiresAt'>, now: number): boolean {
  return isDeadlinePast(session.expiresAt, now) || isDeadlinePast(session.absoluteExpiresAt, now)
}

/**
 * Freshness computed from `rotatedAt`, never read off the row's own `fresh`
 * flag. Fails closed on a `rotatedAt` nothing can read, since this is the gate
 * in front of password changes.
 */
/**
 * Fresh is the AND of two things, and the column alone is neither.
 *
 * The clock half decays: `now - rotatedAt < freshnessMs`. Only `touch` ever
 * rewrote the stored flag, so on its own the column let a session written
 * `fresh: true` and left alone claim freshness for as long as it lived.
 *
 * The stored half revokes: `rotateOrCreate({ purpose: 'step-up' })` demotes the
 * session the caller is stepping up *from* by writing `fresh: false` onto a row
 * whose `rotatedAt` is seconds old. Recomputing from the clock alone would hand
 * that demotion straight back. A stored `false` is therefore sticky - freshness
 * decays with time and can be revoked early, but storage can never grant it.
 */
export function isSessionFresh(
  session: Pick<Sessions.Me, 'rotatedAt' | 'fresh'>,
  now: number,
  freshnessMs: number,
): boolean {
  if (session.fresh !== true) return false
  const ms = deadlineMs(session.rotatedAt)
  return Number.isFinite(ms) && now - ms < freshnessMs
}

/**
 * Resolve a plaintext SID to (session, identity), used by `AuthEngine.resolveSession`.
 *
 * Returns `null` for every ordinary miss: unknown SID, expired `expiresAt`, expired
 * `absoluteExpiresAt`, expired impersonation window. Expired rows are deleted as a
 * side effect.
 *
 * @throws {AuthError} `AUTH_SESSION_REVOKED` with `reason: 'identity-erased'` when the
 * session row is live but its `identityId` no longer resolves. This is a data-integrity
 * violation, not an ordinary expiry, and is deliberately NOT collapsed into `null`:
 * callers must surface it rather than treat it as a plain sign-out.
 */
export async function resolveBySid<Profile extends Identities.ProfileMetadataBase>(
  sid: string,
  sessions: Sessions.Store,
  identities: Identities.Store<Profile>,
  opts: { expectedTenantId?: string; freshnessMs?: number } = {},
): Promise<{ session: Sessions.Me; identity: Identities.Me<Profile> | null } | null> {
  const hash = sha256(sid)
  const session = await sessions.getByHash(hash)
  if (!session) return null
  // A foreign tenant's token must look absent, not fail. Here rather than in the caller
  // because the erased-identity throw below never hands them the session.
  if (opts.expectedTenantId !== undefined && session.tenantId !== opts.expectedTenantId) return null
  const now = Date.now()
  if (isSessionExpired(session, now)) {
    await sessions.delete(session.id)
    return null
  }
  // Impersonation TTL cap.
  if (session.actingAs?.expiresAt !== undefined && isExpiredAt(session.actingAs.expiresAt, now)) {
    await sessions.delete(session.id)
    return null
  }
  const identity = session.identityId ? await identities.findById(session.identityId) : null
  if (session.identityId && !identity) {
    // Identity erased while session was live; surface as missing" rather than misleading "expired".
    throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'identity-erased' })
  }
  // Recomputed, never read off the row - same rule as `getBySid`. `fresh` is a
  // persisted column that only `touch` ever refreshed, so a session written
  // `fresh: true` and left alone still claimed freshness weeks later. Callers
  // gate re-auth on this field, so a stale `true` is a security hole and a
  // stale `false` is a spurious re-auth prompt.
  const freshnessMs = isFiniteNumber(opts.freshnessMs) ? opts.freshnessMs : DEFAULT_SESSION_CONFIG.freshnessMs
  return { identity, session: { ...session, fresh: isSessionFresh(session, now, freshnessMs) } }
}

/** Factory around {@link SessionsImpl} for functional-style config. */
export function sessions(store: Sessions.Store, events: Events.IBus, cfg?: Partial<Sessions.Cfg>): SessionsImpl {
  return new SessionsImpl(store, events, cfg)
}
