import { type Answer, answer, orNull } from '~/core/answer'
import type { Events } from '~/core/events/events.types'
import { randomToken, sha256 } from '../crypto'
import { AuthError } from '../errors'
import type { Identities } from '../identities/identities.types'
import { isFiniteNumber } from '../predicates/predicates'
import type { TenantContext } from '../tenant/tenant.types'
import { DEFAULT_SESSION_CONFIG, SESSION_COLUMN_CAPS } from './sessions.constants'
import { isFactorMethod, type Sessions } from './sessions.types'

/** Which rotations carry an open impersonation window across. Keyed by purpose, so a new one is a build
 *  error until someone decides. */
const ACTING_AS_SURVIVES_ROTATION: Record<Sessions.RotateInput['purpose'], boolean> = {
  'credential-change': true,
  'guest-promotion': false,
  'impersonate-release': false,
  'impersonate-start': false,
  're-auth': false,
  'sign-up': false,
  signin: false,
  'step-down': true,
  'step-up': true,
}

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
      // Spread rather than defaulted: unset has to stay unset, because the field's absence is what means
      // "no cap" and any number here would be a cap nobody asked for.
      ...(this.cfg?.maxSessionsPerIdentity !== undefined && {
        maxSessionsPerIdentity: this.cfg.maxSessionsPerIdentity,
      }),
    }
  }

  /** `session.id` is the hashed row key, `sid` the plaintext for `Transport.issue()`; only the sha-256
   *  of it is ever stored, and the same holds for `csrfToken`.
   *  Raises `AUTH_STALE_WRITE` when the identity's sessions were revoked wholesale while this one was
   *  being minted. Not retried here: the point of the refusal is that a revoke stops a sign-in already
   *  in flight, and re-stamping the clock to get past it would undo exactly that. Whether to attempt
   *  the sign-in again is the caller's. `createdAt` is read from the clock below, so the re-mint
   *  `rotateOrCreate` does straight after its own sweep is never the one refused. */
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
        !('method' in f && isFactorMethod(f.method)) ||
        !('completedAt' in f && f.completedAt instanceof Date)
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
    // Both only ever shorten; the configured TTLs stay the ceiling.
    const capMs = isFiniteNumber(input.ttlMs) && input.ttlMs > 0 ? now + input.ttlMs : Number.POSITIVE_INFINITY
    const maxExpiresAtMs = input.maxExpiresAt === undefined ? Number.POSITIVE_INFINITY : input.maxExpiresAt.getTime()
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
      expiresAt: new Date(Math.min(now + this._cfg.ttlMs, maxExpiresAtMs, capMs)),
      absoluteExpiresAt: new Date(Math.min(now + this._cfg.absoluteTtlMs, capMs)),
      fresh: true,
    }

    await this._store.create(session)
    await this._events.emit('session.created', { session, identity: input.identity ?? null })
    // After the write, never before it: evicting first would drop a live session and then, if this
    // create failed, leave the person with fewer than they started with and no replacement.
    const cap = this._cfg.maxSessionsPerIdentity
    if (cap !== undefined && input.identityId) {
      const all = await this._store.listByIdentity(input.identityId)
      const excess = all.length - cap
      if (excess > 0) {
        // Oldest first by `createdAt`, and the one just minted is the newest, so it is never its own
        // victim however low the cap is set.
        const doomed = [...all].sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime()).slice(0, excess)
        await this.revokeByHashes(doomed.map((s) => s.id))
      }
    }
    return { session, sid, csrfToken }
  }

  /** One code path for every transition that changes a session's identity, AAL or privilege, so
   *  fixation is structurally impossible to forget. */
  async rotateOrCreate(input: Sessions.RotateInput): Promise<{ session: Sessions.Me; sid: string; csrfToken: string }> {
    // Read before any branch sweeps it: `credential-change` deletes the row below and its marker is the
    // only copy of the window. Inheriting never extends, since the window's own `expiresAt` comes with it.
    const previousSid = input.previousSid
    const prevHash =
      typeof previousSid === 'string' && previousSid.length > 0 && previousSid.length <= 4096
        ? sha256(previousSid)
        : null
    const prev = prevHash === null ? null : await orNull(this._store.getByHash(prevHash))
    const minted =
      input.actingAs === undefined && prev?.actingAs && ACTING_AS_SURVIVES_ROTATION[input.purpose]
        ? { ...input, actingAs: prev.actingAs }
        : input
    if (input.purpose === 'credential-change') {
      if (input.identityId) {
        const identityId = input.identityId
        const doomed = await this._store.listByIdentity(identityId)
        await this._store.deleteAllForIdentity(identityId)
        await Promise.all(doomed.map((s) => this._events.emit('session.revoked', { sessionId: s.id, identityId })))
      }
      // A guest has no identity to sweep; it still mints and rotates.
      const fresh = await this.create(minted)
      await this._events.emit('session.rotated', {
        session: fresh.session,
        ...(input.previousSid !== undefined && { previousSessionId: sha256(input.previousSid) }),
      })
      return fresh
    }

    const fresh = await this.create(minted)
    if (prevHash !== null) {
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
          // `fresh: false`. A privileged op has to step up again. Reuses the row read above.
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
    if (s.actingAs) {
      await this._events.emit('identity.impersonation.ended', {
        endedBy: 'revoke',
        realIdentityId: s.actingAs.realIdentityId,
        sessionId: s.id,
        targetIdentityId: s.identityId,
      })
    }

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
        await this._events.emit('session.expired', {
          identityId: session.identityId,
          reason: expiredReason(session, now),
          sessionId: session.id,
        })
        throw new AuthError('AUTH_SESSION_EXPIRED', { expiredAt: expiredAtMs(session, now) })
      }
      // Every caller of this is a privilege gate, and the window was enforced only in `resolveBySid`.
      if (session.actingAs && isImpersonationWindowClosed(session.actingAs, now)) {
        await this._store.delete(session.id).catch(() => {})
        await this._events.emit('session.expired', {
          identityId: session.identityId,
          reason: 'impersonation',
          sessionId: session.id,
        })
        await this._events.emit('identity.impersonation.ended', {
          endedBy: 'expiry',
          realIdentityId: session.actingAs.realIdentityId,
          sessionId: session.id,
          targetIdentityId: session.identityId,
        })
        throw new AuthError('AUTH_IMPERSONATE_WINDOW_CLOSED', { closedAt: windowClosedAtMs(session.actingAs, now) })
      }

      return { ...session, fresh: isSessionFresh(session, now, this._cfg.freshnessMs) }
    })
  }

  /** Extends `expiresAt` without rotating the SID; `fresh` still decays from `rotatedAt`.
   *  SECURITY: guarded, because almost every authenticated request issues one of these and `fresh` is the
   *  flag a sensitive operation re-authenticates on. Unguarded, a `touch` reading just before a
   *  credential-change wrote `fresh: false` put `true` back on top of it, so the password change that was
   *  meant to force a re-auth was undone by the next request the browser made. Retried once; a second
   *  conflict is genuine contention and is the caller's to see. */
  touch(sid: string): Answer.Me<Sessions.Me> {
    return answer(async () => {
      assertSid(sid)
      for (let attempt = 0; ; attempt++) {
        const s = await this._store.getByHash(sha256(sid))
        const now = Date.now()
        // Fail closed on either deadline, so `touch` cannot revive what `resolveBySid` would reject.
        if (isSessionExpired(s, now)) {
          // Cleanup, not the gate, as in `getBySid`.
          await this._store.delete(s.id).catch(() => {})
          await this._events.emit('session.expired', {
            identityId: s.identityId,
            reason: expiredReason(s, now),
            sessionId: s.id,
          })
          throw new AuthError('AUTH_SESSION_EXPIRED', { expiredAt: expiredAtMs(s, now) })
        }
        if (s.actingAs && isImpersonationWindowClosed(s.actingAs, now)) {
          await this._store.delete(s.id).catch(() => {})
          await this._events.emit('session.expired', {
            identityId: s.identityId,
            reason: 'impersonation',
            sessionId: s.id,
          })
          await this._events.emit('identity.impersonation.ended', {
            endedBy: 'expiry',
            realIdentityId: s.actingAs.realIdentityId,
            sessionId: s.id,
            targetIdentityId: s.identityId,
          })
          throw new AuthError('AUTH_IMPERSONATE_WINDOW_CLOSED', { closedAt: windowClosedAtMs(s.actingAs, now) })
        }
        // The guard above rejected everything else, so the cap below is a real number and never `NaN`.
        const absoluteExpiresAtMs = deadlineMs(s.absoluteExpiresAt)
        // Not redundant given the mint-time cap: `create` is public and takes `actingAs` with no `ttlMs`.
        const windowMs = s.actingAs ? deadlineMs(s.actingAs.expiresAt) : Number.POSITIVE_INFINITY
        const newExpiresAt = new Date(Math.min(absoluteExpiresAtMs, now + this._cfg.ttlMs, windowMs))

        try {
          return await this._store.update(
            s.id,
            { expiresAt: newExpiresAt, fresh: isSessionFresh(s, now, this._cfg.freshnessMs) },
            s.updatedAt,
          )
        } catch (err) {
          if (attempt > 0 || !(err instanceof AuthError) || err.code !== 'AUTH_STALE_WRITE') throw err
        }
      }
    })
  }

  /** Every session the store holds for an identity, for an "active devices" view.
   *  WARN: not filtered by deadline — an outright-expired row still appears here until `gc` sweeps it.
   *  An impersonation no longer does, because its row now dies with its window.
   *  `csrfHash` is stripped, as it is at every `/session` endpoint and in the GDPR export: this row is
   *  built to be handed to the person it belongs to, and the browser holds the plaintext in its cookie
   *  and never needs the hash. The store's `listByIdentity` still answers whole rows, which is what the
   *  revoke and concurrency paths read.
   *  WARN: pass a `ctx` in a multi-tenant deployment. Identities are global, so an unscoped call shows
   *  tenant A the same person's tenant B sessions, IP and user-agent included. */
  async listForIdentity(identityId: string, ctx?: TenantContext): Promise<Sessions.Public[]> {
    const rows = await this._store.listByIdentity(identityId, ctx)
    return rows.map(({ csrfHash: _csrfHash, ...view }) => view)
  }

  /** The caller schedules it, under a leader lock in a distributed deployment. */
  async gc(): Promise<{ deleted: number }> {
    const result = await this._store.gc(Date.now())
    // One aggregate emit: the store answers a count, not the rows, so there are no ids to name. Silent
    // when it took nothing, or a gauge keyed on this would see a stream of zero-sized sweeps.
    if (result.deleted > 0) await this._events.emit('session.expired', { count: result.deleted, reason: 'gc' })
    return result
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

  /**
   * Every session for the identity except the one `keepSid` names - "log out all other devices".
   *
   * SECURITY: an unrecognised `keepSid` revokes everything. Failing closed, because the alternative is
   * silently keeping a session the caller did not mean to keep, and a typo would then read as success.
   * Pass a `ctx` in a multi-tenant deployment, for the reason {@link SessionsImpl.listForIdentity} gives.
   */
  async revokeAllExcept(identityId: string, keepSid: string, ctx?: TenantContext): Promise<{ revoked: number }> {
    // Not `assertSid`: a malformed sid here is a caller mistake, and throwing would leave every other
    // device signed in, which is the wrong way to be wrong for this particular button.
    const keepHash =
      typeof keepSid === 'string' && keepSid.length > 0 && keepSid.length <= 4096 ? sha256(keepSid) : null
    const all = await this._store.listByIdentity(identityId, ctx)
    const gone = await this.revokeByHashes(all.filter((s) => s.id !== keepHash).map((s) => s.id))
    // What the store actually removed, not what was asked for: a row that expired in between was not
    // revoked by this call and should not be counted as though it were.
    return { revoked: gone.length }
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

/** A window that has closed, or that carries a date nothing can read. */
function isImpersonationWindowClosed(actingAs: Sessions.ActingAs, now: number): boolean {
  return isDeadlinePast(actingAs.expiresAt, now)
}

/** The instant the window closed. `now` stands in for a date nothing can read. */
function windowClosedAtMs(actingAs: Sessions.ActingAs, now: number): number {
  const ms = deadlineMs(actingAs.expiresAt)
  return Number.isFinite(ms) ? ms : now
}

/** The deadline the session fell past, for `AUTH_SESSION_EXPIRED` to name. `now` is the floor, so a
 *  deadline nothing can read — which {@link isSessionExpired} counts as past — still answers an instant. */
function expiredAtMs(session: Pick<Sessions.Me, 'expiresAt' | 'absoluteExpiresAt'>, now: number): number {
  return Math.min(...[session.expiresAt, session.absoluteExpiresAt].map(deadlineMs).filter(Number.isFinite), now)
}

/** Which of the two deadlines it fell past, for `session.expired` to name. The absolute cap wins a tie,
 *  because it is the one a renewal cannot move. */
function expiredReason(
  session: Pick<Sessions.Me, 'expiresAt' | 'absoluteExpiresAt'>,
  now: number,
): 'sliding' | 'absolute' {
  return isDeadlinePast(session.absoluteExpiresAt, now) ? 'absolute' : 'sliding'
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
 * tenant reject `AUTH_SESSION_REVOKED`, each with its own `reason`; either deadline rejects
 * `AUTH_SESSION_EXPIRED` and an elapsed impersonation window `AUTH_IMPERSONATE_WINDOW_CLOSED`, which name
 * the instant instead. All three are in the absent set, so the facet's `orNull()` reads every one of them
 * back as null. An expired row is deleted on the way past.
 *
 * @throws {AuthError} `AUTH_SESSION_IDENTITY_ERASED` when the row is live but its `identityId` no longer
 * resolves. SECURITY: that code is deliberately outside the absent set, so a caller reading this through
 * `orNull()` still sees a data-integrity violation rather than a plain sign-out.
 */
export async function resolveBySid<Profile extends Identities.ProfileMetadataBase>(
  sid: string,
  sessions: Sessions.Store,
  identities: Identities.Store<Profile>,
  opts: {
    expectedTenantId?: string
    freshnessMs?: number
    /** Called when a row is refused for age, so the caller can emit `session.expired` from a bus this
     *  function has no business holding. It must not throw: it runs between the delete and the refusal,
     *  and anything it raises replaces `AUTH_SESSION_EXPIRED` with itself. */
    onExpired?: (info: {
      sessionId: string
      identityId: string | null
      reason: 'sliding' | 'absolute' | 'impersonation'
    }) => void
  } = {},
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
    opts.onExpired?.({
      identityId: session.identityId,
      reason: expiredReason(session, now),
      sessionId: session.id,
    })
    throw new AuthError('AUTH_SESSION_EXPIRED', { expiredAt: expiredAtMs(session, now) })
  }
  if (session.actingAs && isImpersonationWindowClosed(session.actingAs, now)) {
    // Cleanup, not the gate, as in `getBySid`.
    await sessions.delete(session.id).catch(() => {})
    opts.onExpired?.({ identityId: session.identityId, reason: 'impersonation', sessionId: session.id })
    throw new AuthError('AUTH_IMPERSONATE_WINDOW_CLOSED', { closedAt: windowClosedAtMs(session.actingAs, now) })
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
