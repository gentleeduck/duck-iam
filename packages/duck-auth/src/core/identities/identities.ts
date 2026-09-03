import { BATCH_NOT_FOUND, type Batch, batchResult, loopFallback } from '~/core/batch'
import { withActor } from '../actor'
import { getProfileString } from '../credentials/credentials'
import type { Credential } from '../credentials/credentials.types'
import { AuthError } from '../errors'
import type { Events } from '../events'
import type { Sessions } from '../sessions/sessions.types'
import type { TenantContext } from '../tenant/tenant.types'
import { DEFAULT_IDENTITIES_CONFIG } from './identities.constants'
import type { Identities } from './identities.types'

/**
 * Identities facet - CRUD + linking + merging + GDPR primitives.
 * Optimistic locking discipline: every write that mutates `Identity` flows
 * through `update(expectedVersion)`; callers that pass a stale version see
 * `AUTH/STALE_WRITE` and decide retry/surface.
 */
/**
 * Outcome id for a provider link. One identity may appear several times in a
 * batch - two links for the same person - so keying outcomes by identity alone
 * would collide and silently drop rows.
 */
function linkKey(identityId: string, providerId: string): string {
  return `${identityId} ${providerId}`
}

export class IdentitiesImpl<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase> {
  constructor(
    private readonly _store: Identities.Store<Profile>,
    private readonly _events: Events.IBus,
    private readonly _cfg: Identities.Cfg = DEFAULT_IDENTITIES_CONFIG,
  ) {}

  /**
   * Public read of the configured soft-delete grace period. Sibling
   * facets (FlowsImpl.requestAccountDeletion) need it to compute the
   * caller-visible `restorableUntil` deadline; the legacy approach
   * reached into `_cfg` via an `as unknown as { _cfg }` double-cast
   * which both broke encapsulation and was an unsafe runtime assumption
   * (other constructors might not have the same private name). Read-only.
   */
  get softDeleteGracePeriodMs(): number {
    return this._cfg.softDeleteGracePeriodMs
  }

  // --- lookup -----------------------------------------------------------

  async getById(id: string): Promise<Identities.Me<Profile> | null> {
    return this._store.findById(id)
  }

  async getByEmail(email: string): Promise<Identities.Me<Profile> | null> {
    // RFC 5321 cap + typeof guard: prevents multi-MB lookups + non-string crashes
    // before reaching adapter.
    if (typeof email !== 'string' || email.length === 0 || email.length > 254) return null
    return this._store.findByEmail(email.trim().toLowerCase())
  }

  async getByProviderSub(providerId: string, sub: string): Promise<Identities.Me<Profile> | null> {
    // Defensive caps; both keys flow into SQL `=`-comparisons + JSONB extracts.
    if (typeof providerId !== 'string' || providerId.length === 0 || providerId.length > 128) return null
    if (typeof sub !== 'string' || sub.length === 0 || sub.length > 512) return null
    return this._store.findByProviderSub(providerId, sub)
  }

  // --- create / update --------------------------------------------------

  async create(input: {
    profile: Profile
    tenantId?: string
    providers?: Identities.ProviderLink[]
    emailVerified?: boolean
  }): Promise<Identities.Me<Profile>> {
    this._assertProfileWithinCap(input.profile)
    const created = await this._store.create({
      profile: input.profile,
      providers: input.providers ?? [],
      emailVerified: input.emailVerified ?? false,
    })
    await this._events.emit('signup.completed', { identity: created })
    return created
  }

  async updateProfile(
    id: string,
    profilePatch: Partial<Profile>,
    expectedVersion: number,
  ): Promise<Identities.Me<Profile>> {
    const cur = await this._store.findById(id)
    if (!cur) throw new AuthError('AUTH_UNAUTHENTICATED')
    const nextProfile = { ...(cur.profile ?? {}), ...profilePatch } as Profile
    this._assertProfileWithinCap(nextProfile)
    return this._store.update(id, { profile: nextProfile }, expectedVersion)
  }

  /**
   * bound the serialized profile size to defend the identity store
   * (and every downstream `findById` / `findByEmail` that materializes
   * it) from amplification. With no cap, an attacker who can drive a
   * sign-up route or profile-update flow can store multi-MB profiles
   * indefinitely - each read amplifies the per-request cost and the
   * underlying row balloons. JSON byte length (UTF-8) is the right
   * proxy: it matches what gets serialized to the database column,
   * encrypted at rest, and emitted over the wire. Default 16 KiB
   * comfortably accommodates typical profiles (email + display name +
   * picture URL + locale + a few custom fields) without leaving the
   * door open to multi-MB blobs. Operators with richer schemas can
   * raise via `profiles.profileMaxBytes`.
   */
  private _assertProfileWithinCap(profile: Profile): void {
    const cap = this._cfg.profileMaxBytes
    if (cap === undefined || cap <= 0) return
    let bytes: number
    try {
      bytes = Buffer.byteLength(JSON.stringify(profile) ?? '', 'utf8')
    } catch {
      // JSON.stringify can throw on circular refs / BigInt. Fail closed
      // - the operator should not store unserializable values anyway.
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

  // --- provider linking ------------------------------------------------

  /** Answers with the identity as it stands after the link, providers included. */
  async link(identityId: string, link: Omit<Identities.ProviderLink, 'addedAt'>): Promise<Identities.Me<Profile>> {
    const cur = await this._store.findById(identityId)
    if (!cur) throw new AuthError('AUTH_UNAUTHENTICATED')
    // Reject duplicate provider link for same identity.
    if (cur.providers.some((p) => p.providerId === link.providerId)) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: link.providerId,
        detail: 'already linked',
      })
    }
    const linked = await this._store.link(identityId, { ...link, addedAt: new Date() })
    // `null` here means the row disappeared between the read above and the
    // write - the same condition the read rejected, so it gets the same answer.
    if (!linked) throw new AuthError('AUTH_UNAUTHENTICATED')
    await this._events.emit('identity.linked', { identityId, providerId: link.providerId })
    return linked
  }

  /** Answers with the identity as it stands after the link is dropped. */
  async unlink(identityId: string, providerId: string): Promise<Identities.Me<Profile>> {
    const cur = await this._store.findById(identityId)
    if (!cur) throw new AuthError('AUTH_UNAUTHENTICATED')
    // Don't allow unlinking the last credential surface - leaves account inaccessible.
    if (cur.providers.length <= 1) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId,
        detail: 'cannot unlink last provider; add another method first',
      })
    }
    const unlinked = await this._store.unlink(identityId, providerId)
    if (!unlinked) throw new AuthError('AUTH_UNAUTHENTICATED')
    return unlinked
  }

  /** Answers with the survivor, carrying the union of both provider lists. */
  async merge(survivorId: string, dupId: string): Promise<Identities.Me<Profile>> {
    if (survivorId === dupId) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: 'merge',
        detail: 'survivor and dup are the same identity',
      })
    }
    // The store re-points the dup's credentials and sessions and then deletes
    // it, so a survivor that does not exist would destroy the dup and orphan
    // everything that pointed at it. Refuse before any of that runs.
    if (!(await this._store.findById(survivorId))) throw new AuthError('AUTH_UNAUTHENTICATED')
    const survivor = await this._store.merge(survivorId, dupId)
    if (!survivor) throw new AuthError('AUTH_UNAUTHENTICATED')
    await this._events.emit('identity.merged', {
      survivorId,
      mergedFromId: dupId,
    })
    return survivor
  }

  // --- soft-delete / restore / erase ----------------------------------

  /**
   * Answers with the hidden row - its `deletedAt` is when the grace window
   * closes, so a caller can tell the user how long they have to change their
   * mind without a second read. `null` when no such identity.
   */
  async softDelete(id: string): Promise<Identities.Me<Profile> | null> {
    return this._store.softDelete(id, this._cfg.softDeleteGracePeriodMs)
  }

  /**
   * Clears a soft delete. `null` means the id matched nothing, the same as
   * {@link softDelete} and {@link erase}. A row that WAS matched and then
   * refused throws instead, carrying which rule refused it -
   * `AUTH_GRACE_EXPIRED` when the window has closed, `AUTH_EMAIL_TAKEN` when
   * a live row now holds its address.
   */
  async restore(id: string): Promise<Identities.Me<Profile> | null> {
    return this._store.restore(id)
  }

  /**
   * Hard-erase. Audit-logged for compliance. Cannot be undone. Answers with the
   * row as it was immediately before deletion - the caller's last chance to
   * record what went, since a second read would find nothing.
   */
  async erase(id: string, opts: { reason: string; operatorId?: string }): Promise<Identities.Me<Profile> | null> {
    // `operatorId` used to be accepted and dropped on the floor. It now binds
    // the ambient actor for the duration, so anything the erase cascades into
    // is attributed to the operator who asked for it rather than to whoever
    // the request happened to be running as.
    // Bound only when there is something to bind: `withActor(undefined, ...)`
    // is a fence that clears the scope - the same as `withTenant` - so passing
    // an omitted `operatorId` straight through would erase a request-scoped
    // actor the caller had already established.
    const erased = await (opts.operatorId === undefined
      ? this._store.erase(id)
      : withActor(opts.operatorId, () => this._store.erase(id)))
    // `reason` stays the caller's to log: the library does not own the shape of
    // a compliance audit envelope.
    return erased
  }

  // --- bulk -------------------------------------------------------------

  /**
   * Bulk import. Used for migrations from legacy systems. Skips already-existing
   * identities by email (mode='skipExisting') or merges into existing
   * (mode='merge'). Returns counts so caller can surface to ops.
   */
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
        const email = extractEmail(row.profile)
        const existing = email ? await this._store.findByEmail(email) : null
        if (existing && mode === 'skipExisting') {
          skipped++
          continue
        }
        if (existing && mode === 'merge') {
          // Link any new providers without duplicating; do not patch profile here.
          for (const link of row.providers ?? []) {
            if (!existing.providers.some((p) => p.providerId === link.providerId)) {
              await this._store.link(existing.id, link)
            }
          }
          skipped++
          continue
        }
        if (existing && mode === 'replace') {
          await this._store.erase(existing.id)
        }
        await this.create(row)
        created++
      } catch {
        failed++
      }
    }
    return { created, skipped, failed }
  }

  // --- GDPR export ------------------------------------------------------

  /**
   * Portable export under GDPR right-to-access. Argon2id secrets, oauth
   * tokens, recovery code hashes, and other credential `secret` fields are
   * always stripped. Sessions are exported separately by Sessions facet if
   * the consumer wants them.
   */
  async exportAll(
    id: string,
    credentials: Credential.Store,
    ctx: TenantContext = {},
    opts: { sessions?: Sessions.Store } = {},
  ): Promise<Identities.ExportBlob<Profile>> {
    const identity = await this._store.findById(id)
    if (!identity) throw new AuthError('AUTH_UNAUTHENTICATED')
    const creds = await credentials.listByIdentity(id, null, ctx)
    const sessions = opts.sessions ? await opts.sessions.listByIdentity(id) : []
    return {
      identity,
      credentials: creds.map(({ secret: _secret, ...rest }) => rest),
      sessions: sessions.map(({ csrfHash: _csrfHash, ...rest }) => rest),
      schemaVersion: '1',
      exportedAt: Date.now(),
    }
  }

  /**
   * Serialise an `ExportBlob` to a canonical JSON string suitable for
   * delivery to the user (file download / portable archive). Stable
   * key ordering across runs so checksum comparisons work.
   */
  static exportToJson<P extends Identities.ProfileMetadataBase>(blob: Identities.ExportBlob<P>): string {
    return JSON.stringify(blob, sortKeys, 2)
  }

  // --- batch ----------------------------------------------------------

  /**
   * Soft-deletes many identities. One statement when the store supports it,
   * otherwise one call per id. Reports per-row outcomes: an id with no live
   * identity is `not-found`, not an exception.
   */
  async softDeleteMany(ids: readonly string[]): Promise<Batch.Result> {
    if (ids.length === 0) return batchResult([])
    if (this._store.softDeleteMany) {
      return this._store.softDeleteMany(ids, this._cfg.softDeleteGracePeriodMs)
    }
    return loopFallback(ids, async (id) => {
      if (!(await this._store.findById(id))) return BATCH_NOT_FOUND
      await this._store.softDelete(id, this._cfg.softDeleteGracePeriodMs)
    })
  }

  /**
   * Restores many soft-deleted identities. See {@link softDeleteMany}.
   *
   * `restore` answers `null` for an id that matched nothing and throws for its
   * two real refusals - the grace window has closed, someone else now holds the
   * address - so the loop passes both shapes through: `null` becomes
   * `not-found`, and `loopFallback` maps each thrown code to its own reason.
   * Flattening them into one outcome would report all three as `not-found`,
   * which is true of only the first: the other two rows are still there and are
   * being refused.
   */
  async restoreMany(ids: readonly string[]): Promise<Batch.Result<Identities.Me<Profile>>> {
    if (ids.length === 0) return batchResult([])
    if (this._store.restoreMany) return this._store.restoreMany(ids)
    return loopFallback(ids, async (id) => (await this._store.restore(id)) ?? BATCH_NOT_FOUND)
  }

  /** Hard-erases many identities. Cannot be undone. See {@link softDeleteMany}. */
  async eraseMany(ids: readonly string[]): Promise<Batch.Result> {
    if (ids.length === 0) return batchResult([])
    if (this._store.eraseMany) return this._store.eraseMany(ids)
    // `erase` hands back the row it removed, so the loop can report a miss
    // without the extra read the set-based path never needed either.
    return loopFallback(ids, async (id) => {
      if (!(await this._store.erase(id))) return BATCH_NOT_FOUND
    })
  }

  /**
   * Updates many profiles, each against its own expected version. Rows that
   * lose the optimistic-lock race are reported as `stale-write`; the rest still
   * apply. Every patch is resolved and cap-checked before anything is written,
   * so an oversized profile fails the batch rather than half-applying it.
   */
  async updateProfileMany(
    rows: readonly { id: string; patch: Partial<Profile>; expectedVersion: number }[],
  ): Promise<Batch.Result<Identities.Me<Profile>>> {
    if (rows.length === 0) return batchResult([])

    const resolved: { id: string; profile: Profile; expectedVersion: number }[] = []
    const missing: Batch.Outcome<Identities.Me<Profile>>[] = []
    for (const row of rows) {
      const cur = await this._store.findById(row.id)
      if (!cur) {
        missing.push({ id: row.id, ok: false, reason: 'not-found' })
        continue
      }
      const next = { ...cur.profile, ...row.patch }
      this._assertProfileWithinCap(next)
      resolved.push({ expectedVersion: row.expectedVersion, id: row.id, profile: next })
    }

    const byId = new Map<string, Batch.Outcome<Identities.Me<Profile>>>()
    if (resolved.length > 0) {
      const applied = this._store.updateProfileMany
        ? await this._store.updateProfileMany(resolved)
        : await loopFallback(
            resolved.map((r) => r.id),
            async (id) => {
              const r = resolved.find((x) => x.id === id)
              if (!r) return BATCH_NOT_FOUND
              return this._store.update(id, { profile: r.profile }, r.expectedVersion)
            },
          )
      for (const o of applied.outcomes) byId.set(o.id, o)
    }
    for (const m of missing) byId.set(m.id, m)

    // Re-assemble in the caller's input order - `missing` rows never reached the store.
    return batchResult(rows.map((r) => byId.get(r.id) ?? { id: r.id, ok: false, reason: 'not-found' as const }))
  }

  /**
   * Links several provider identities at once. Emits one `identity.linked` per
   * link that actually landed.
   */
  async linkMany(
    links: readonly { identityId: string; link: Omit<Identities.ProviderLink, 'addedAt'> }[],
  ): Promise<Batch.Result> {
    if (links.length === 0) return batchResult([])
    const stamped = links.map((l) => ({ identityId: l.identityId, link: { ...l.link, addedAt: new Date() } }))
    const result = this._store.linkMany
      ? await this._store.linkMany(stamped)
      : await loopFallback(
          stamped.map((l) => linkKey(l.identityId, l.link.providerId)),
          async (key) => {
            const entry = stamped.find((l) => linkKey(l.identityId, l.link.providerId) === key)
            if (!entry) return BATCH_NOT_FOUND
            await this._store.link(entry.identityId, entry.link)
          },
        )
    for (const [i, outcome] of result.outcomes.entries()) {
      const entry = stamped[i]
      if (outcome.ok && entry) {
        await this._events.emit('identity.linked', {
          identityId: entry.identityId,
          providerId: entry.link.providerId,
        })
      }
    }
    return result
  }

  /** Unlinks several provider identities at once. */
  async unlinkMany(links: readonly { identityId: string; providerId: string }[]): Promise<Batch.Result> {
    if (links.length === 0) return batchResult([])
    if (this._store.unlinkMany) return this._store.unlinkMany(links)
    return loopFallback(
      links.map((l) => linkKey(l.identityId, l.providerId)),
      async (key) => {
        const entry = links.find((l) => linkKey(l.identityId, l.providerId) === key)
        if (!entry) return BATCH_NOT_FOUND
        await this._store.unlink(entry.identityId, entry.providerId)
      },
    )
  }
}

/** Trim + lowercase the `email` field off a profile; `undefined` when absent or non-string. */
function extractEmail(profile: unknown): string | undefined {
  const raw = getProfileString(profile, 'email')
  if (raw === undefined) return undefined
  const trimmed = raw.trim().toLowerCase()
  return trimmed.length > 0 ? trimmed : undefined
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

/** Factory around {@link Identities} for functional-style config. */
export function identities<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  store: Identities.Store<Profile>,
  events: Events.IBus,
  cfg?: Identities.Cfg,
): IdentitiesImpl<Profile> {
  return new IdentitiesImpl(store, events, cfg)
}
