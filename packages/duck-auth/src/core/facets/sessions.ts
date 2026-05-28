import { isExpiredAt, isFiniteNumber } from '../credential-utils'
import { randomToken, sha256 } from '../crypto'
import { AuthErrorObject } from '../errors'
import type { TenantContext } from '../types/context'
import type { Events } from '../types/events'
import type { Identity } from '../types/identity'
import type { Session } from '../types/session'

export const DEFAULT_SESSION_CONFIG: SessionsFacet.IConfig = {
  ttlMs: 7 * 24 * 60 * 60 * 1000,
  absoluteTtlMs: 30 * 24 * 60 * 60 * 1000,
  freshnessMs: 5 * 60 * 1000,
}

/**
 * Sessions facet - the only path that creates / rotates / revokes sessions.
 * Every privilege-changing transition routes through {@link rotateOrCreate}
 * so the session-fixation discipline lives in exactly one place.
 *
 * Resolution is on `AuthRoot.resolveSession()` rather than here because the
 * Transport contract drives extraction; this facet owns lifecycle only.
 */
export class SessionsFacet {
  constructor(
    private readonly _store: Session.IStore,
    private readonly _events: Events.IBus,
    private readonly _cfg: SessionsFacet.IConfig = DEFAULT_SESSION_CONFIG,
  ) {}

  /**
   * Build a fresh session record + persist it.
   *
   * Returns `{ session, sid }` where `session.id` is the **hashed** row key
   * (used internally + as the audit-log identifier) and `sid` is the
   * **plaintext** session identifier - the value the caller passes to
   * `Transport.issue()` to put on the wire. The plaintext sid never appears
   * on the persisted row; only its sha-256 hash does.
   */
  async create(
    input: SessionsFacet.ICreateInput,
  ): Promise<{ session: Session.ISession; sid: string; csrfToken: string }> {
    // Cap factors length so a buggy caller can't bloat the session row's
    // JSON column. Real flows mint sessions with 1-3 factors.
    if (!Array.isArray(input.factors) || input.factors.length > 16) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'sessions.create: factors must be an array <=16',
      })
    }
    const sid = randomToken(32)
    // Mint plaintext for the cookie, store only the hash on the row.
    const csrfToken = randomToken(32)
    const now = Date.now()
    const session: Session.ISession = {
      id: sha256(sid),
      identityId: input.identityId,
      kind: input.kind,
      aal: input.aal,
      factors: input.factors,
      csrfHash: sha256(csrfToken),
      createdAt: now,
      rotatedAt: now,
      expiresAt: now + this._cfg.ttlMs,
      absoluteExpiresAt: now + this._cfg.absoluteTtlMs,
      fresh: true,
    }
    if (input.tenantId !== undefined) session.tenantId = input.tenantId
    // Persist truncated ip/UA so a hostile header cannot bloat the session row.
    if (typeof input.ip === 'string' && input.ip.length > 0) session.ip = input.ip.slice(0, 64)
    if (typeof input.userAgent === 'string' && input.userAgent.length > 0) {
      session.userAgent = input.userAgent.slice(0, 512)
    }
    if (input.fingerprint !== undefined) session.fingerprint = input.fingerprint
    if (input.actingAs !== undefined) session.actingAs = input.actingAs

    await this._store.create(session)
    await this._events.emit('session.created', { session, identity: null })
    return { session, sid, csrfToken }
  }

  /**
   * DESIGN section 37 rotation matrix. Single code path for every transition that
   * changes a session's identity, AAL, or privilege. The library asserts that
   * flow handlers always route through this method so fixation is structurally
   * impossible to forget.
   */
  async rotateOrCreate(
    input: SessionsFacet.IRotateInput,
  ): Promise<{ session: Session.ISession; sid: string; csrfToken: string }> {
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
          // Old SID is downgraded, not deleted - long-lived tabs keep working,
          // but at the prior AAL with fresh=false. Re-step-up is required for
          // privileged ops.
          const prev = await this._store.getByHash(prevHash)
          if (prev) {
            await this._store.update(prev.id, { aal: prev.aal, fresh: false })
          }
          break
        }
        case 'credential-change':
          // Every other session for this identity is revoked cross-device.
          if (input.identityId) {
            const all = await this._store.listByIdentity(input.identityId)
            for (const s of all) {
              if (s.id === fresh.session.id) continue
              await this._store.delete(s.id)
              await this._events.emit('session.revoked', {
                sessionId: s.id,
                identityId: input.identityId,
              })
            }
          }
          break
        case 'impersonate-start':
          // Real session is preserved alongside the new actingAs session; no revoke.
          break
      }
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

  /** Revoke every session belonging to an identity (used by credential-change paths). */
  async revokeAllForIdentity(identityId: string): Promise<void> {
    const all = await this._store.listByIdentity(identityId)
    await this._store.deleteAllForIdentity(identityId)
    for (const s of all) {
      await this._events.emit('session.revoked', {
        sessionId: s.id,
        identityId,
      })
    }
  }

  /** Resolve a plaintext SID to its session row (no identity join). */
  async getBySid(sid: string): Promise<Session.ISession | null> {
    // Defensive typeof + length cap; sha256(non-string) throws + multi-MB
    // input bloats hashing.
    if (typeof sid !== 'string' || sid.length === 0 || sid.length > 4096) return null
    return this._store.getByHash(sha256(sid))
  }

  /** Refresh expiresAt by ttlMs without rotating the SID. Stops fresh-window slip. */
  async touch(sid: string): Promise<Session.ISession | null> {
    if (typeof sid !== 'string' || sid.length === 0 || sid.length > 4096) return null
    const hash = sha256(sid)
    const s = await this._store.getByHash(hash)
    if (!s) return null
    const now = Date.now()
    // fail closed if absoluteExpiresAt is non-finite (adapter bug).
    // `NaN < now === false` would otherwise extend a should-be-dead
    // session past its absolute cap.
    if (!isFiniteNumber(s.absoluteExpiresAt) || s.absoluteExpiresAt < now) {
      await this._store.delete(s.id)
      return null
    }
    const newExpiresAt = Math.min(s.absoluteExpiresAt, now + this._cfg.ttlMs)
    const fresh = now - s.rotatedAt < this._cfg.freshnessMs
    return this._store.update(s.id, { expiresAt: newExpiresAt, fresh })
  }

  /** List all live sessions for an identity. Used by UI's "active devices" view. */
  async listForIdentity(identityId: string): Promise<Session.ISession[]> {
    return this._store.listByIdentity(identityId)
  }

  /** Periodic GC. Caller schedules under leader-lock for distributed deployments. */
  async gc(): Promise<{ deleted: number }> {
    return this._store.gc(Date.now())
  }

  /** Create a guest session - no identity, AAL=1, kind='guest'. Promotable on signin. */
  async createGuest(
    opts: { tenantId?: string; ip?: string; userAgent?: string } = {},
  ): Promise<{ session: Session.ISession; sid: string }> {
    return this.create({
      identityId: null,
      kind: 'guest',
      aal: 1,
      factors: [],
      ...(opts.tenantId !== undefined && { tenantId: opts.tenantId }),
      ...(opts.ip !== undefined && { ip: opts.ip }),
      ...(opts.userAgent !== undefined && { userAgent: opts.userAgent }),
    })
  }

  /** Promote a guest session to an authed session. SID rotates; carts/drafts move by identity. */
  async promoteGuest(input: {
    guestSid: string
    identityId: string
    factors: Session.Factor[]
    aal: Session.AAL
    tenantId?: string
    ip?: string
    userAgent?: string
  }): Promise<{ session: Session.ISession; sid: string }> {
    return this.rotateOrCreate({
      purpose: 'guest-promotion',
      previousSid: input.guestSid,
      identityId: input.identityId,
      kind: 'user',
      aal: input.aal,
      factors: input.factors,
      ...(input.tenantId !== undefined && { tenantId: input.tenantId }),
      ...(input.ip !== undefined && { ip: input.ip }),
      ...(input.userAgent !== undefined && { userAgent: input.userAgent }),
    })
  }
}

/** Resolve a plaintext SID to (session, identity) - used by AuthRoot.resolveSession. */
export async function resolveBySid<Profile = unknown>(
  sid: string,
  sessions: Session.IStore,
  identities: Identity.IStore<Profile>,
  ctx: TenantContext,
): Promise<{ session: Session.ISession; identity: Identity.IIdentity<Profile> | null } | null> {
  const hash = sha256(sid)
  const session = await sessions.getByHash(hash)
  if (!session) return null
  const now = Date.now()
  // Fail closed on non-finite expiry (adapter bug) since `NaN < now` is false.
  if (
    !isFiniteNumber(session.expiresAt) ||
    session.expiresAt < now ||
    !isFiniteNumber(session.absoluteExpiresAt) ||
    session.absoluteExpiresAt < now
  ) {
    await sessions.delete(session.id)
    return null
  }
  // Impersonation TTL cap.
  if (session.actingAs?.expiresAt !== undefined && isExpiredAt(session.actingAs.expiresAt, now)) {
    await sessions.delete(session.id)
    return null
  }
  const identity = session.identityId ? await identities.findById(session.identityId, ctx) : null
  if (session.identityId && !identity) {
    // Identity erased while session was live; surface as "missing" rather than misleading "expired".
    throw new AuthErrorObject('AUTH/SESSION_REVOKED', { reason: 'identity-erased' })
  }
  return { session, identity }
}

/**
 * Namespace merge - SessionsFacet.IConfig, SessionsFacet.ICreateInput,
 * SessionsFacet.IRotateInput. Flat names kept for backwards compatibility.
 */
export namespace SessionsFacet {
  export interface IConfig {
    /** Sliding TTL in ms. Default 7 days. */
    ttlMs: number
    /** Hard absolute cap in ms. Default 30 days. */
    absoluteTtlMs: number
    /** Window in ms where a session counts as "fresh" since the last factor. Default 5 min. */
    freshnessMs: number
  }

  export interface ICreateInput {
    identityId: string | null
    kind: Session.Kind
    aal: Session.AAL
    factors: Session.Factor[]
    tenantId?: string
    ip?: string
    userAgent?: string
    fingerprint?: string
    actingAs?: Session.ActingAs
  }

  export interface IRotateInput extends ICreateInput {
    /**
     * DESIGN section 37 rotation matrix. Drives whether the previous SID is revoked
     * outright, downgraded (step-up old-SID kept alive at lower AAL), or left
     * alone (impersonation start runs alongside the original session).
     */
    purpose:
      | 'signin'
      | 're-auth'
      | 'step-up'
      | 'step-down'
      | 'credential-change'
      | 'impersonate-start'
      | 'impersonate-release'
      | 'guest-promotion'
    previousSid?: string
  }
}
