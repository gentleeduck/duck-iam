import { BATCH_NOT_FOUND, type Batch, batchResult, loopFallback } from '~/core/batch'
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

  async link(identityId: string, link: Omit<Identities.ProviderLink, 'addedAt'>): Promise<void> {
    const cur = await this._store.findById(identityId)
    if (!cur) throw new AuthError('AUTH_UNAUTHENTICATED')
    // Reject duplicate provider link for same identity.
    if (cur.providers.some((p) => p.providerId === link.providerId)) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: link.providerId,
        detail: 'already linked',
      })
    }
    await this._store.link(identityId, { ...link, addedAt: new Date() })
    await this._events.emit('identity.linked', { identityId, providerId: link.providerId })
  }

  async unlink(identityId: string, providerId: string): Promise<void> {
    const cur = await this._store.findById(identityId)
    if (!cur) throw new AuthError('AUTH_UNAUTHENTICATED')
    // Don't allow unlinking the last credential surface - leaves account inaccessible.
    if (cur.providers.length <= 1) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId,
        detail: 'cannot unlink last provider; add another method first',
      })
    }
    await this._store.unlink(identityId, providerId)
  }

  async merge(survivorId: string, dupId: string): Promise<void> {
    if (survivorId === dupId) {
      throw new AuthError('AUTH_PROVIDER_FAILED', {
        providerId: 'merge',
        detail: 'survivor and dup are the same identity',
      })
    }
    await this._store.merge(survivorId, dupId)
    await this._events.emit('identity.merged', {
      survivorId,
      mergedFromId: dupId,
    })
  }

  // --- soft-delete / restore / erase ----------------------------------

  async softDelete(id: string): Promise<void> {
    await this._store.softDelete(id, this._cfg.softDeleteGracePeriodMs)
  }

  async restore(id: string): Promise<Identities.Me<Profile>> {
    return this._store.restore(id)
  }

  /** Hard-erase. Audit-logged for compliance. Cannot be undone. */
  async erase(id: string, opts: { reason: string; operatorId?: string }): Promise<void> {
    await this._store.erase(id)
    // Caller emits its own compliance event with reason; library stays out of
    // the audit-envelope shape for the erase action.
    void opts
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

  /** Restores many soft-deleted identities. See {@link softDeleteMany}. */
  async restoreMany(ids: readonly string[]): Promise<Batch.Result<Identities.Me<Profile>>> {
    if (ids.length === 0) return batchResult([])
    if (this._store.restoreMany) return this._store.restoreMany(ids)
    return loopFallback(ids, async (id) => {
      try {
        return await this._store.restore(id)
      } catch {
        // `restore` throws on an id that was never there; in a batch that is a
        // per-row miss, not a reason to abandon the remaining ids.
        return BATCH_NOT_FOUND
      }
    })
  }

  /** Hard-erases many identities. Cannot be undone. See {@link softDeleteMany}. */
  async eraseMany(ids: readonly string[]): Promise<Batch.Result> {
    if (ids.length === 0) return batchResult([])
    if (this._store.eraseMany) return this._store.eraseMany(ids)
    return loopFallback(ids, (id) => this._store.erase(id))
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
