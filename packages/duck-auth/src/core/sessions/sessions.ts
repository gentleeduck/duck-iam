import { type Answer, answer, orNull } from '~/core/answer'
import type { Events } from '~/core/events/events.types'
import { randomToken, sha256 } from '../crypto'
import { AuthError } from '../errors'
import type { Identities } from '../identities/identities.types'
import { isExpiredAt, isFiniteNumber } from '../predicates/predicates'
import type { TenantContext } from '../tenant/tenant.types'
import { DEFAULT_SESSION_CONFIG, SESSION_COLUMN_CAPS } from './sessions.constants'
import { AUTH_SESSION_FACTOR_METHODS, type Sessions } from './sessions.types'

/** Every privilege-changing transition routes through {@link SessionsImpl.rotateOrCreate}, so the
 *  fixation discipline lives in one place. */
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

  /** `session.id` is the hashed row key, `sid` the plaintext for `Transport.issue()`; only the sha-256
   *  of it is ever stored, and the same holds for `csrfToken`. */
  async create(input: Sessions.MintInput): Promise<{ session: Sessions.Me; sid: string; csrfToken: string }> {
    // Real flows mint 1 to 3; the cap is so a buggy caller cannot bloat the JSON column.
    if (!Array.isArray(input.factors) || input.factors.length > 16) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'sessions.create: factors must be an array <=16',
      })
    }
    // Contents, not just the shape: the Redis reader drops an unlisted method or a non-Date
    // `completedAt`, so an unchecked row would not read back intact.
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
    // Refused here, where it can be named, rather than by every later read of it.
    if (input.actingAs) {
      const startedAt = input.actingAs.startedAt?.getTime() ?? Number.NaN
      const expiresAt = input.actingAs.expiresAt?.getTime() ?? Number.NaN
      if (!(expiresAt > Date.now()) || !(expiresAt > startedAt)) {
        throw new AuthError('AUTH_INVALID_PARAMETERS', {
          detail: 'sessions.create: actingAs must open before it closes, and close in the future',
        })
      }
    }
    const sid = randomToken(32)
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
      // Truncated, so a hostile header cannot bloat the row.
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
      updatedAt: nowDate,
      rotatedAt: nowDate,
      expiresAt: new Date(
        input.maxExpiresAt === undefined
          ? now + this._cfg.ttlMs
          : Math.min(now + this._cfg.ttlMs, input.maxExpiresAt.getTime()),
      ),
      absoluteExpiresAt: new Date(now + this._cfg.absoluteTtlMs),
      fresh: true,
    }

    await this._store.create(session)
    await this._events.emit('session.created', { session, identity: input.identity ?? null })
    return { session, sid, csrfToken }
  }

  /** One code path for every transition that changes a session's identity, AAL or privilege, so
   *  fixation is structurally impossible to forget. */
  async rotateOrCreate(input: Sessions.RotateInput): Promise<{ session: Sessions.Me; sid: string; csrfToken: string }> {
    if (input.purpose === 'credential-change') {
      if (input.identityId) {
        const identityId = input.identityId
        const doomed = await this._store.listByIdentity(identityId)
        await this._store.deleteAllForIdentity(identityId)
        await Promise.all(doomed.map((s) => this._events.emit('session.revoked', { sessionId: s.id, identityId })))
      }
      // A guest has no identity to sweep; it still mints and rotates.
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
          // Downgraded, not deleted, so long-lived tabs keep working at the prior AAL with
          // `fresh: false`. A privileged op has to step up again.
          const prev = await orNull(this._store.getByHash(prevHash))
          if (prev) {
            await this._store.update(prev.id, { aal: prev.aal, fresh: false })
          }
          break
        }
        case 'impersonate-start':
          // The real session runs alongside the impersonating one.
          break
        default: {
          // A new purpose without a revocation decision is a build error, not a silent no-op.
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

  /** Answers the row that went, so a caller can name the device. A session already gone throws, so
   *  `orNull()` is how a caller asks for a repeat revoke to read as the no-op it is. */
  revoke(sid: string): Answer.Me<Sessions.Me> {
    return answer(() => {
      assertSid(sid)

      return this._revoke(sha256(sid))
    })
  }

  /** {@link SessionsImpl.revoke} for a caller holding the stored hash rather than the plaintext SID. */
  revokeByHash(sessionId: string): Answer.Me<Sessions.Me> {
    return answer(this._revoke(sessionId))
  }

  private async _revoke(hash: string): Promise<Sessions.Me> {
    const s = await this._store.getByHash(hash)
    await this._store.delete(s.id)
    await this._events.emit('session.revoked', { sessionId: s.id, identityId: s.identityId })

    return s
  }

  /** Answers the rows, so "signed out of 4 devices" needs no second query. */
  async revokeAllForIdentity(identityId: string, ctx?: TenantContext): Promise<Sessions.Me[]> {
    const all = await this._store.listByIdentity(identityId, ctx)
    await this._store.deleteAllForIdentity(identityId, ctx)
    await Promise.all(all.map((s) => this._events.emit('session.revoked', { sessionId: s.id, identityId })))
    return all
  }

  /**
   * SECURITY: the deadline gate is here rather than in the store, which only knows "the row under this key". Two
   * callers hand the answer straight to `rotateOrCreate`, so without it an expired sid is resurrected.
   * `fresh` is recomputed from `rotatedAt` for the same reason.
   */
  getBySid(sid: string): Answer.Me<Sessions.Me> {
    return answer(async () => {
      assertSid(sid)
      const session = await this._store.getByHash(sha256(sid))
      const now = Date.now()
      if (isSessionExpired(session, now)) {
        // A row nobody can use should not wait for `gc` to come round to it, as in `resolveBySid`.
        // Cleanup, not the gate: the refusal below is already decided and `gc` sweeps the row either way.
        // Awaited bare, a failed delete threw AUTH_ADAPTER_FAILED in its place — and that code is not in
        // `ABSENT`, so `resolveSession().orNull()` rethrew it and an expired session read as a 500.
        await this._store.delete(session.id).catch(() => {})
        throw new AuthError('AUTH_SESSION_EXPIRED', { expiredAt: expiredAtMs(session, now) })
      }

      return { ...session, fresh: isSessionFresh(session, now, this._cfg.freshnessMs) }
    })
  }

  /** Extends `expiresAt` without rotating the SID; `fresh` still decays from `rotatedAt`. */
  touch(sid: string): Answer.Me<Sessions.Me> {
    return answer(async () => {
      assertSid(sid)
      const s = await this._store.getByHash(sha256(sid))
      const now = Date.now()
      // Fail closed on either deadline, so `touch` cannot revive what `resolveBySid` would reject.
      if (isSessionExpired(s, now)) {
        // Cleanup, not the gate, as in `getBySid`.
        await this._store.delete(s.id).catch(() => {})
        throw new AuthError('AUTH_SESSION_EXPIRED', { expiredAt: expiredAtMs(s, now) })
      }
      // The guard above rejected everything else, so the cap below is a real number and never `NaN`.
      const absoluteExpiresAtMs = deadlineMs(s.absoluteExpiresAt)
      const newExpiresAt = new Date(Math.min(absoluteExpiresAtMs, now + this._cfg.ttlMs))

      return this._store.update(s.id, {
        expiresAt: newExpiresAt,
        fresh: isSessionFresh(s, now, this._cfg.freshnessMs),
      })
    })
  }

  /** Every live session for an identity, for an "active devices" view.
   *  WARN: pass a `ctx` in a multi-tenant deployment. Identities are global, so an unscoped call shows
   *  tenant A the same person's tenant B sessions, IP and user-agent included. */
  async listForIdentity(identityId: string, ctx?: TenantContext): Promise<Sessions.Me[]> {
    return this._store.listByIdentity(identityId, ctx)
  }

  /** The caller schedules it, under a leader lock in a distributed deployment. */
  async gc(): Promise<{ deleted: number }> {
    return this._store.gc(Date.now())
  }

  /** Mints a session carrying no identity, for a caller who has not signed in yet. */
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

  /** The SID rotates, so anything the guest owned has to move by identity. */
  async promoteGuest(input: {
    guestSid: string
    identityId: string
    factors: Sessions.Factor[]
    aal: Sessions.AAL
    tenantId?: string
    ip?: string
    userAgent?: string
    /** Passthrough for a caller that already holds the row. */
    identity?: Identities.Me | null
    /** Carried over, so guest device-binding survives promotion. */
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

  /** One statement for the set. An identity that had none is simply absent from the answer. */
  async revokeAllForIdentities(identityIds: string[]): Promise<Sessions.Revoked[]> {
    if (identityIds.length === 0) return []
    const gone = await this._store.deleteAllForIdentities(identityIds)

    for (const s of gone) await this._events.emit('session.revoked', { identityId: s.identityId, sessionId: s.id })

    return gone
  }

  /** {@link SessionsImpl.revokeAllForIdentities} keyed by session id rather than identity. */
  async revokeByHashes(ids: string[]): Promise<Sessions.Revoked[]> {
    if (ids.length === 0) return []
    const gone = await this._store.deleteMany(ids)

    for (const s of gone) await this._events.emit('session.revoked', { identityId: s.identityId, sessionId: s.id })

    return gone
  }
}

/** Epoch ms, or `NaN` when the value is not a readable date. */
/** `sha256` throws on a non-string, and a multi-MB one would bloat the hash. */
function assertSid(sid: string): void {
  if (typeof sid !== 'string' || sid.length === 0 || sid.length > 4096) {
    throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'sid is empty or longer than 4096 characters' })
  }
}

function deadlineMs(v: unknown): number {
  if (v instanceof Date) return v.getTime()
  return isFiniteNumber(v) ? v : Number.NaN
}

/** Past, or unreadable at all.
 *  WARN: not `isExpiredAt`, which reads a missing value as "never expires": right for an optional
 *  impersonation window, backwards here, and `NaN < now` is false. */
function isDeadlinePast(v: unknown, now: number): boolean {
  const ms = deadlineMs(v)
  return !Number.isFinite(ms) || ms < now
}

/** Either deadline: the sliding idle timeout, or the hard absolute cap. */
export function isSessionExpired(session: Pick<Sessions.Me, 'expiresAt' | 'absoluteExpiresAt'>, now: number): boolean {
  return isDeadlinePast(session.expiresAt, now) || isDeadlinePast(session.absoluteExpiresAt, now)
}

/** The deadline the session fell past, for `AUTH_SESSION_EXPIRED` to name. `now` is the floor, so a
 *  deadline nothing can read — which {@link isSessionExpired} counts as past — still answers an instant. */
function expiredAtMs(session: Pick<Sessions.Me, 'expiresAt' | 'absoluteExpiresAt'>, now: number): number {
  return Math.min(...[session.expiresAt, session.absoluteExpiresAt].map(deadlineMs).filter(Number.isFinite), now)
}

/**
 * Fresh is the clock AND the column, never either alone: the clock decays, and a stored `false` revokes
 * early, since `rotateOrCreate({ purpose: 'step-up' })` demotes a session whose `rotatedAt` is seconds
 * old. Storage can revoke freshness but never grant it.
 *
 * SECURITY: fails closed on a `rotatedAt` nothing can read, and on one dated ahead of the clock, because
 * this gates password changes. `now - ms` alone is negative for a future stamp and so under any window,
 * which made a session dated a day out permanently fresh - measured, a century out read fresh too. Nothing
 * bounds the column from above: `chk_auth_sessions_rotated_after_created` is a floor, and the stamp is
 * written by whichever node rotated the session, so one machine with a skewed clock hands the whole fleet
 * sessions that never go stale. `JwtTransport.verify` and `checkStepUp` already weigh the same distance
 * with `Math.abs`; this is the predicate they were meant to agree with.
 */
export function isSessionFresh(
  session: Pick<Sessions.Me, 'rotatedAt' | 'fresh'>,
  now: number,
  freshnessMs: number,
): boolean {
  if (session.fresh !== true) return false
  const ms = deadlineMs(session.rotatedAt)
  return Number.isFinite(ms) && Math.abs(now - ms) < freshnessMs
}

/**
 * Resolve a plaintext SID to (session, identity) for `AuthEngine.resolveSession`. An unknown SID, a foreign
 * tenant and an elapsed impersonation window reject `AUTH_SESSION_REVOKED`, each with its own `reason`;
 * either deadline rejects `AUTH_SESSION_EXPIRED`, which names the instant instead. Both codes are in the
 * absent set, so the facet's `orNull()` reads every one of them back as null. An expired row is deleted on
 * the way past.
 *
 * @throws {AuthError} `AUTH_SESSION_IDENTITY_ERASED` when the row is live but its `identityId` no longer
 * resolves. SECURITY: that code is deliberately outside the absent set, so a caller reading this through
 * `orNull()` still sees a data-integrity violation rather than a plain sign-out.
 */
export async function resolveBySid<Profile extends Identities.ProfileMetadataBase>(
  sid: string,
  sessions: Sessions.Store,
  identities: Identities.Store<Profile>,
  opts: { expectedTenantId?: string; freshnessMs?: number } = {},
): Promise<{ session: Sessions.Me; identity: Identities.Me<Profile> | null }> {
  const hash = sha256(sid)
  const session = await orNull(sessions.getByHash(hash))
  if (!session) throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'no session for that sid' })
  // A foreign tenant's token must look absent, not fail, and the throw below never hands it over.
  if (opts.expectedTenantId !== undefined && session.tenantId !== opts.expectedTenantId) {
    throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'the session belongs to another tenant' })
  }
  const now = Date.now()
  if (isSessionExpired(session, now)) {
    // Cleanup, not the gate, as in `getBySid`.
    await sessions.delete(session.id).catch(() => {})
    throw new AuthError('AUTH_SESSION_EXPIRED', { expiredAt: expiredAtMs(session, now) })
  }
  if (session.actingAs?.expiresAt !== undefined && isExpiredAt(session.actingAs.expiresAt, now)) {
    // Cleanup, not the gate, as in `getBySid`.
    await sessions.delete(session.id).catch(() => {})
    throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'the impersonation window has closed' })
  }
  const identity = session.identityId ? await orNull(identities.find({ id: session.identityId })) : null
  if (session.identityId && !identity) {
    // Erased while the session was live: surface it as missing rather than as a misleading "expired".
    throw new AuthError('AUTH_SESSION_IDENTITY_ERASED')
  }
  // SECURITY: recomputed, never read off the row, as in `getBySid`. Callers gate re-auth on this, so a
  // stale `true` is a hole and a stale `false` a spurious prompt.
  const freshnessMs = isFiniteNumber(opts.freshnessMs) ? opts.freshnessMs : DEFAULT_SESSION_CONFIG.freshnessMs
  return { identity, session: { ...session, fresh: isSessionFresh(session, now, freshnessMs) } }
}

export function sessions(store: Sessions.Store, events: Events.IBus, cfg?: Partial<Sessions.Cfg>): SessionsImpl {
  return new SessionsImpl(store, events, cfg)
}
