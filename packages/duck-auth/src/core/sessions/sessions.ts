import { BATCH_NOT_FOUND, type Batch, batchResult, loopFallback } from '~/core/batch'
import type { Events } from '~/core/events/events.types'
import { isExpiredAt, isFiniteNumber } from '../credentials/credentials'
import { randomToken, sha256 } from '../crypto'
import { AuthError } from '../errors'
import type { Identities } from '../identities/identities.types'
import { DEFAULT_SESSION_CONFIG } from './sessions.constants'
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
      // Persist truncated ip/UA so a hostile header cannot bloat the session row.
      ip: typeof input.ip === 'string' && input.ip.length > 0 ? input.ip.slice(0, 64) : null,
      userAgent:
        typeof input.userAgent === 'string' && input.userAgent.length > 0 ? input.userAgent.slice(0, 512) : null,
      // Header-derived like ip/UA, so capped the same way. 256 matches the library's
      // other opaque-identifier caps.
      fingerprint:
        typeof input.fingerprint === 'string' && input.fingerprint.length > 0 ? input.fingerprint.slice(0, 256) : null,
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

  /** Revoke a single session by plaintext SID. */
  async revoke(sid: string): Promise<void> {
    if (typeof sid !== 'string' || sid.length === 0 || sid.length > 4096) return
    const hash = sha256(sid)
    const s = await this._store.getByHash(hash)
    if (!s) return
    await this._store.delete(s.id)
    await this._events.emit('session.revoked', {
      sessionId: s.id,
      identityId: s.identityId,
    })
  }

  /** Revoke by session id (the stored hash). Use when you have ISession.id but not the plaintext SID. */
  async revokeByHash(sessionId: string): Promise<void> {
    const s = await this._store.getByHash(sessionId)
    if (!s) return
    await this._store.delete(s.id)
    await this._events.emit('session.revoked', { sessionId: s.id, identityId: s.identityId })
  }

  /** Revoke every session belonging to an identity (used by credential-change paths). */
  async revokeAllForIdentity(identityId: string): Promise<void> {
    const all = await this._store.listByIdentity(identityId)
    await this._store.deleteAllForIdentity(identityId)
    await Promise.all(all.map((s) => this._events.emit('session.revoked', { sessionId: s.id, identityId })))
  }

  /** Resolve a plaintext SID to its session row (no identity join). */
  async getBySid(sid: string): Promise<Sessions.Me | null> {
    // Defensive typeof + length cap; authSha256(non-string) throws + multi-MB
    // input bloats hashing.
    if (typeof sid !== 'string' || sid.length === 0 || sid.length > 4096) return null
    return this._store.getByHash(sha256(sid))
  }

  /** Refresh expiresAt by ttlMs without rotating the SID. Stops fresh-window slip. */
  async touch(sid: string): Promise<Sessions.Me | null> {
    if (typeof sid !== 'string' || sid.length === 0 || sid.length > 4096) return null
    const hash = sha256(sid)
    const s = await this._store.getByHash(hash)
    if (!s) return null
    const now = Date.now()
    const absoluteExpiresAtMs =
      s.absoluteExpiresAt instanceof Date
        ? s.absoluteExpiresAt.getTime()
        : isFiniteNumber(s.absoluteExpiresAt)
          ? (s.absoluteExpiresAt as number)
          : Number.NaN
    // fail closed if absoluteExpiresAt is non-finite (adapter bug).
    // `NaN < now === false` would otherwise extend a should-be-dead
    // session past its absolute cap.
    if (!Number.isFinite(absoluteExpiresAtMs) || absoluteExpiresAtMs < now) {
      await this._store.delete(s.id)
      return null
    }
    const expiresAtMs =
      s.expiresAt instanceof Date
        ? s.expiresAt.getTime()
        : isFiniteNumber(s.expiresAt)
          ? (s.expiresAt as number)
          : Number.NaN
    // Fail closed on a non-finite or already-passed sliding expiry. Without this, touch()
    // revives a session that resolveBySid would have rejected.
    if (!Number.isFinite(expiresAtMs) || expiresAtMs < now) {
      await this._store.delete(s.id)
      return null
    }
    const rotatedAtMs = s.rotatedAt instanceof Date ? s.rotatedAt.getTime() : (s.rotatedAt as number)
    const newExpiresAt = new Date(Math.min(absoluteExpiresAtMs, now + this._cfg.ttlMs))
    const fresh = now - rotatedAtMs < this._cfg.freshnessMs
    return this._store.update(s.id, { expiresAt: newExpiresAt, fresh })
  }

  /** List all live sessions for an identity. Used by UI's "active devices view. */
  async listForIdentity(identityId: string): Promise<Sessions.Me[]> {
    return this._store.listByIdentity(identityId)
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
  opts: { expectedTenantId?: string } = {},
): Promise<{ session: Sessions.Me; identity: Identities.Me<Profile> | null } | null> {
  const hash = sha256(sid)
  const session = await sessions.getByHash(hash)
  if (!session) return null
  // A foreign tenant's token must look absent, not fail. Here rather than in the caller
  // because the erased-identity throw below never hands them the session.
  if (opts.expectedTenantId !== undefined && session.tenantId !== opts.expectedTenantId) return null
  const now = Date.now()
  const expiresAtMs =
    session.expiresAt instanceof Date
      ? session.expiresAt.getTime()
      : isFiniteNumber(session.expiresAt)
        ? (session.expiresAt as number)
        : Number.NaN
  const absExpiresAtMs =
    session.absoluteExpiresAt instanceof Date
      ? session.absoluteExpiresAt.getTime()
      : isFiniteNumber(session.absoluteExpiresAt)
        ? (session.absoluteExpiresAt as number)
        : Number.NaN
  // Fail closed on non-finite expiry (adapter bug) since `NaN < now` is false.
  if (!Number.isFinite(expiresAtMs) || expiresAtMs < now || !Number.isFinite(absExpiresAtMs) || absExpiresAtMs < now) {
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
  return { session, identity }
}

/** Factory around {@link SessionsImpl} for functional-style config. */
export function sessions(store: Sessions.Store, events: Events.IBus, cfg?: Partial<Sessions.Cfg>): SessionsImpl {
  return new SessionsImpl(store, events, cfg)
}
