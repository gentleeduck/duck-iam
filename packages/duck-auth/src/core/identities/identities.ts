import { type Answer, answer, orNull } from '~/core/answer'
import { withActor } from '../actor'
import { isStandingFactor, toPublicCredential } from '../credentials/credentials'
import type { Credential } from '../credentials/credentials.types'
import { AuthError } from '../errors'
import type { Events } from '../events'
import { getProfileString } from '../predicates/predicates'
import type { Sessions } from '../sessions/sessions.types'
import type { TenantContext } from '../tenant/tenant.types'
import { DEFAULT_IDENTITIES_CONFIG } from './identities.constants'
import type { Identities } from './identities.types'

export function isSoftDeleted(row: { deletedAt?: Date | number | null }): boolean {
  return row.deletedAt != null
}

/** Every mutating write goes through `update(expectedVersion)`, so a stale caller sees `AUTH_STALE_WRITE`. */
export class IdentitiesImpl<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase> {
  constructor(
    private readonly _store: Identities.Store<Profile>,
    private readonly _events: Events.IBus,
    private readonly _cfg: Identities.Cfg = DEFAULT_IDENTITIES_CONFIG,
    /** Read by {@link IdentitiesImpl.unlink} alone, to count the ways in that are not links. Absent means none can be. */
    private readonly _credentials?: Credential.Store,
  ) {}

  /** Exposed for `FlowsImpl.requestAccountDeletion`, which needs it for `restorableUntil`. */
  get softDeleteGracePeriodMs(): number {
    return this._cfg.softDeleteGracePeriodMs
  }

  /** The identity with this id. */
  getById(id: string): Answer.Me<Identities.Me<Profile>> {
    return answer(this._store.find({ id }))
  }

  /** The identity holding this email address. */
  getByEmail(email: string): Answer.Me<Identities.Me<Profile>> {
    return answer(() => {
      // RFC 5321 cap, so a multi-MB or non-string lookup never reaches the adapter.
      assertKey(email, 254, 'email')

      return this._store.find({ email })
    })
  }

  /** The identity linked to this provider's subject. */
  getByProviderSub(providerId: string, sub: string): Answer.Me<Identities.Me<Profile>> {
    return answer(() => {
      assertKey(providerId, 128, 'providerId')
      assertKey(sub, 512, 'providerSub')

      return this._store.find({ providerId, providerSub: sub })
    })
  }

  /** Creates an identity, with its provider links in the same write. */
  async create(input: {
    profile: Profile
    tenantId?: string
    providers?: Identities.ProviderLinkInput[]
    emailVerified?: boolean
  }): Promise<Identities.Me<Profile>> {
    this.assertProfileWithinCap(input.profile)
    const created = await this._store.create({
      profile: input.profile,
      providers: input.providers ?? [],
      emailVerified: input.emailVerified ?? false,
    })
    await this._events.emit('signup.completed', { identity: created })
    return created
  }

  /** Merges a partial profile onto the row, refusing a concurrent edit. */
  async updateProfile(
    id: string,
    profilePatch: Partial<Profile>,
    expectedVersion: number,
  ): Promise<Identities.Me<Profile>> {
    const cur = await orNull(this._store.find({ id }))
    if (!cur) throw new AuthError('AUTH_UNAUTHENTICATED')
    const nextProfile = { ...(cur.profile ?? {}), ...profilePatch } as Profile
    this.assertProfileWithinCap(nextProfile)
    return this._store.update(id, { profile: nextProfile }, expectedVersion)
  }

  /**
   * A lost version race is retried once, since the caller has already spent their single-use token.
   *
   * SECURITY: the column, never the profile. `updateProfile` merges a caller-supplied patch without
   * filtering keys, so routing verification through it would let the account holder assert it.
   */
  async markEmailVerified(id: string): Promise<Identities.Me<Profile>> {
    let lastErr: unknown
    for (let attempt = 0; attempt < 2; attempt++) {
      const cur = await orNull(this._store.find({ id }))
      if (!cur) throw new AuthError('AUTH_UNAUTHENTICATED')
      if (cur.emailVerified) return cur
      try {
        return await this._store.update(id, { emailVerified: true }, cur.version)
      } catch (err) {
        if (!(err instanceof AuthError) || err.code !== 'AUTH_STALE_WRITE') throw err
        lastErr = err
      }
    }
    throw lastErr
  }

  /** Public and typed `unknown` because the signup flow stages a partial profile for up to 24 hours, and
   *  a cap the profile only meets on the last hop is not a cap. */
  assertProfileWithinCap(profile: unknown): void {
    const cap = this._cfg.profileMaxBytes
    if (cap === undefined || cap <= 0) return
    let bytes: number
    try {
      bytes = Buffer.byteLength(JSON.stringify(profile) ?? '', 'utf8')
    } catch {
      // JSON.stringify throws on a circular ref or a BigInt.
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'identity profile is not JSON-serializable',
      })
    }
    if (bytes > cap) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `identity profile exceeds size cap (${bytes} > ${cap} bytes)`,
      })
    }
  }

  /** Refuses a provider the identity already holds, where the store takes a repeat as a no-op. */
  async link(identityId: string, link: Identities.ProviderLinkInput): Promise<Identities.Me<Profile>> {
    const cur = await orNull(this._store.find({ id: identityId }))
    if (!cur) throw new AuthError('AUTH_UNAUTHENTICATED')
    if (cur.providers.some((p) => p.providerId === link.providerId)) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: link.providerId,
        detail: 'already linked',
      })
    }
    const linked = await orNull(this._store.link(identityId, link))
    // Null here is the row going between the read and the write, which is what the read already refused.
    if (!linked) throw new AuthError('AUTH_UNAUTHENTICATED')
    await this._events.emit('identity.linked', { identityId, providerId: link.providerId })
    return linked
  }

  /** Across every tenant: the question is whether the account is reachable at all. */
  private async _liveCredentials(identityId: string): Promise<number> {
    if (!this._credentials) return 0
    const rows = await this._credentials.listByIdentity(identityId, null, {})

    return rows.filter(isStandingFactor).length
  }

  /** Drops one provider link from the identity. */
  async unlink(identityId: string, providerId: string): Promise<Identities.Me<Profile>> {
    const cur = await orNull(this._store.find({ id: identityId }))
    if (!cur) throw new AuthError('AUTH_UNAUTHENTICATED')
    // SECURITY: dropping the last way in leaves the account unreachable, so the count is the links that
    // remain plus the credentials, which is where a password lives.
    if (
      cur.providers.filter((p) => p.providerId !== providerId).length + (await this._liveCredentials(identityId)) ===
      0
    ) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId,
        detail: 'cannot unlink last provider; add another method first',
      })
    }
    const unlinked = await orNull(this._store.unlink(identityId, providerId))
    if (!unlinked) throw new AuthError('AUTH_UNAUTHENTICATED')
    // The mirror of `identity.linked`, which `link` has always emitted. This facet dropped a factor
    // silently, so the one write an account takeover performs was the one the audit log could not see.
    // Always `false` here: the override lives on `flows.unlinkProvider`, and this path has none.
    await this._events.emit('identity.unlinked', { allowedLockout: false, identityId, providerId })
    return unlinked
  }

  /** Hides the identity and starts the configured grace period before erasure. */
  softDelete(id: string): Answer.Me<Identities.Me<Profile>> {
    return answer(this._store.softDelete(id, this._cfg.softDeleteGracePeriodMs))
  }

  /** A window already closed throws `AUTH_GRACE_EXPIRED`, as an id matching nothing throws not-found. */
  restore(id: string): Answer.Me<Identities.Me<Profile>> {
    return answer(this._store.restore(id))
  }

  /** Irreversible. Answers the row as it was, since nothing can read it now.
   *  `reason` is the caller's to log: the library does not own the shape of a compliance envelope. */
  erase(id: string, opts: { reason: string; operatorId?: string }): Answer.Me<Identities.Me<Profile>> {
    // Bound only when there is an actor: `withActor(undefined)` is a fence that clears the scope.
    // `async`, because `withActor` is typed to hand back either the value or a promise of it.
    return answer(async () =>
      opts.operatorId === undefined ? this._store.erase(id) : withActor(opts.operatorId, () => this._store.erase(id)),
    )
  }

  /** `skipExisting` passes over an address already present, `merge` folds the new logins into it. */
  async bulkCreate(
    rows: Array<{
      profile: Profile
      tenantId?: string
      providers?: Identities.ProviderLink[]
    }>,
    opts: { mode?: 'skipExisting' | 'merge' | 'replace' } = {},
  ): Promise<{ created: number; skipped: number; failed: number }> {
    const mode = opts.mode ?? 'skipExisting'
    let created = 0
    let skipped = 0
    let failed = 0
    for (const row of rows) {
      try {
        const email = getProfileString(row.profile, 'email')
        const existing = email ? await orNull(this._store.find({ email })) : null
        if (existing && mode === 'skipExisting') {
          skipped++
          continue
        }
        if (existing && mode === 'merge') {
          // Through `link`, so a folded-in provider emits `identity.linked` like every other link and
          // a providerId the row already holds is refused there rather than re-checked here.
          for (const link of row.providers ?? []) {
            await refusable(() => this.link(existing.id, link))
          }
          skipped++
          continue
        }
        if (existing && mode === 'replace') {
          await this._store.erase(existing.id)
        }
        await this.create(row)
        created++
      } catch (err) {
        // The rule `refusable` applies, for the same reason: a refusal this layer decided is a failed
        // row, a driver failure is not. Postgres leaves the transaction aborted once a statement has
        // failed, so counting one here would make a later COMMIT a silent ROLLBACK.
        if (!(err instanceof AuthError) || err.cause !== undefined) throw err
        failed++
      }
    }
    return { created, skipped, failed }
  }

  /** GDPR right-to-access, with every credential `secret` and session `csrfHash` stripped, and both
   *  lists narrowed to `ctx`. */
  async exportAll(
    id: string,
    credentials: Credential.Store,
    ctx: TenantContext = {},
    opts: { sessions?: Sessions.Store } = {},
  ): Promise<Identities.ExportBlob<Profile>> {
    const identity = await orNull(this._store.find({ id }))
    if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')
    const creds = await credentials.listByIdentity(id, null, ctx)
    // SECURITY: scoped like the credentials read a line above, which is the `ctx` this method already
    // took and then dropped here. Identities are global, so the unfiltered list was the one the store
    // contract warns about in so many words: tenant A's right-to-access blob named every session
    // tenant B had issued the same person, carrying that `tenantId`, the ip, the user-agent and the
    // fingerprint of each. `sessions-tenant-scope.test.ts` proved the store and `listForIdentity`
    // honour the filter; this caller was the one that never asked for it. An unscoped `ctx` matches
    // every row, so a single-tenant export answers exactly what it did before.
    const sessions = opts.sessions ? await opts.sessions.listByIdentity(id, ctx) : []
    return {
      identity,
      credentials: creds.map(toPublicCredential),
      sessions: sessions.map(({ csrfHash: _csrfHash, ...rest }) => rest),
      schemaVersion: '1',
      exportedAt: Date.now(),
    }
  }

  /** Stable key ordering, so checksums compare across runs. */
  static exportToJson<P extends Identities.ProfileMetadataBase>(blob: Identities.ExportBlob<P>): string {
    return JSON.stringify(blob, sortKeys, 2)
  }

  /** Soft-deletes every id in one adapter call. */
  async softDeleteMany(ids: string[]): Promise<Identities.Me<Profile>[]> {
    if (ids.length === 0) return []

    return this._store.softDeleteMany(ids, this._cfg.softDeleteGracePeriodMs)
  }

  /** One whose window has closed is left out, as a missing row is, where {@link IdentitiesImpl.restore} throws. */
  async restoreMany(ids: string[]): Promise<Identities.Me<Profile>[]> {
    const restored: Identities.Me<Profile>[] = []
    for (const id of ids) {
      const row = await refusable(() => this._store.restore(id))
      if (row) restored.push(row)
    }

    return restored
  }

  /** Erases every id in one adapter call, under the same envelope {@link IdentitiesImpl.erase} takes:
   *  a batch erasure is no less irreversible for being a batch, so it records who ran it the same way. */
  async eraseMany(ids: string[], opts: { reason: string; operatorId?: string }): Promise<Identities.Me<Profile>[]> {
    if (ids.length === 0) return []
    // Bound once around the one adapter call. Omitting `operatorId` leaves an outer request-scoped
    // actor alone, because `withActor(undefined)` is a fence that clears the scope rather than a no-op.
    return opts.operatorId === undefined
      ? this._store.eraseMany(ids)
      : withActor(opts.operatorId, () => this._store.eraseMany(ids))
  }

  /** The caller schedules it, under a leader lock in a distributed deployment. Until it runs, a row whose
   *  window closed is hidden but still there, which is not what a deletion promised. */
  async gc(): Promise<{ deleted: number }> {
    return this._store.gc(Date.now())
  }

  /** Every patch is cap-checked up front, so one oversized patch fails the whole batch. A lost version
   *  race is left out. */
  async updateProfileMany(
    rows: { id: string; patch: Partial<Profile>; expectedVersion: number }[],
  ): Promise<Identities.Me<Profile>[]> {
    const resolved: { id: string; profile: Profile; expectedVersion: number }[] = []
    for (const row of rows) {
      const cur = await orNull(this._store.find({ id: row.id }))
      if (!cur) continue
      const next = { ...cur.profile, ...row.patch }
      this.assertProfileWithinCap(next)
      resolved.push({ expectedVersion: row.expectedVersion, id: row.id, profile: next })
    }

    const written: Identities.Me<Profile>[] = []
    for (const r of resolved) {
      const row = await refusable(() => this._store.update(r.id, { profile: r.profile }, r.expectedVersion))
      if (row) written.push(row)
    }

    return written
  }

  /** Adds each provider link, one write per identity. Through {@link IdentitiesImpl.link}, so a
   *  providerId already on the identity is skipped here as it is refused there. */
  async linkMany(
    links: { identityId: string; link: Identities.ProviderLinkInput }[],
  ): Promise<Identities.Me<Profile>[]> {
    const linked: Identities.Me<Profile>[] = []
    for (const l of links) {
      const row = await refusable(() => this.link(l.identityId, l.link))
      if (row) linked.push(row)
    }

    return linked
  }

  /** Drops each provider link, one write per identity. Through {@link IdentitiesImpl.unlink}, not the
   *  store: a row that would leave the account with no way in is skipped rather than stranding it, and
   *  the batch is the path a bulk admin action takes, so it is the one that most needs the guard. */
  async unlinkMany(links: { identityId: string; providerId: string }[]): Promise<Identities.Me<Profile>[]> {
    const unlinked: Identities.Me<Profile>[] = []
    for (const l of links) {
      const row = await refusable(() => this.unlink(l.identityId, l.providerId))
      if (row) unlinked.push(row)
    }

    return unlinked
  }
}

/**
 * Runs one row of a batch. A refused write answers null, so the row is left out instead of taking the rest.
 *
 * SECURITY: a driver failure is hard whatever code it carries, and `cause` is what tells it from a refusal
 * this layer's own read decided. Postgres leaves the transaction aborted once a statement has failed, so swallowing
 * one would make COMMIT a silent ROLLBACK.
 */
async function refusable<T>(run: () => Promise<T>): Promise<T | null> {
  try {
    return await run()
  } catch (err) {
    if (!(err instanceof AuthError) || err.cause !== undefined) throw err

    return null
  }
}

/** A lookup key flows into SQL comparisons and JSONB extracts, so the bound is here rather than at the adapter. */
function assertKey(value: string, max: number, name: string): void {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) {
    throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: `${name} is empty or longer than ${max} characters` })
  }
}

function sortKeys(_key: string, value: unknown): unknown {
  const isPlainObject = (v: unknown): v is Record<string, unknown> =>
    typeof v === 'object' && v !== null && !Array.isArray(v)

  if (isPlainObject(value)) {
    const sorted: Record<string, unknown> = {}
    for (const k of Object.keys(value).sort()) {
      sorted[k] = value[k]
    }
    return sorted
  }
  return value
}

export function identities<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  store: Identities.Store<Profile>,
  events: Events.IBus,
  cfg?: Identities.Cfg,
  credentials?: Credential.Store,
): IdentitiesImpl<Profile> {
  return new IdentitiesImpl(store, events, cfg, credentials)
}
