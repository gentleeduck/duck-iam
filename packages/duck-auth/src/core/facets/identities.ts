import { getProfileString } from '../credential-utils'
import { AuthErrorObject } from '../errors'
import type { TenantContext } from '../types/context'
import type { Credential } from '../types/credential'
import type { Events } from '../types/events'
import type { Identity } from '../types/identity'
import type { Session } from '../types/session'

export const DEFAULT_IDENTITIES_CONFIG: IdentitiesFacet.IConfig = {
  softDeleteGracePeriodMs: 7 * 24 * 60 * 60 * 1000,
  profileMaxBytes: 16 * 1024,
}

/**
 * Identities facet - CRUD + linking + merging + GDPR primitives.
 * Optimistic locking discipline: every write that mutates `Identity` flows
 * through `update(expectedVersion)`; callers that pass a stale version see
 * `AUTH/STALE_WRITE` and decide retry/surface.
 */
export class IdentitiesFacet<Profile = unknown> {
  constructor(
    private readonly _store: Identity.IStore<Profile>,
    private readonly _events: Events.IBus,
    private readonly _cfg: IdentitiesFacet.IConfig = DEFAULT_IDENTITIES_CONFIG,
  ) {}

  /**
   * Public read of the configured soft-delete grace period. Sibling
   * facets (FlowsFacet.requestAccountDeletion) need it to compute the
   * caller-visible `restorableUntil` deadline; the legacy approach
   * reached into `_cfg` via an `as unknown as { _cfg }` double-cast
   * which both broke encapsulation and was an unsafe runtime assumption
   * (other constructors might not have the same private name). Read-only.
   */
  get softDeleteGracePeriodMs(): number {
    return this._cfg.softDeleteGracePeriodMs
  }

  // --- lookup -----------------------------------------------------------

  async getById(id: string, ctx: TenantContext = {}): Promise<Identity.IIdentity<Profile> | null> {
    return this._store.findById(id, ctx)
  }

  async getByEmail(email: string, ctx: TenantContext = {}): Promise<Identity.IIdentity<Profile> | null> {
    // RFC 5321 cap + typeof guard: prevents multi-MB lookups + non-string crashes
    // before reaching adapter.
    if (typeof email !== 'string' || email.length === 0 || email.length > 254) return null
    return this._store.findByEmail(email.trim().toLowerCase(), ctx)
  }

  async getByProviderSub(
    providerId: string,
    sub: string,
    ctx: TenantContext = {},
  ): Promise<Identity.IIdentity<Profile> | null> {
    // Defensive caps; both keys flow into SQL `=`-comparisons + JSONB extracts.
    if (typeof providerId !== 'string' || providerId.length === 0 || providerId.length > 128) return null
    if (typeof sub !== 'string' || sub.length === 0 || sub.length > 512) return null
    return this._store.findByProviderSub(providerId, sub, ctx)
  }

  // --- create / update --------------------------------------------------

  async create(
    input: { profile?: Profile; tenantId?: string; providers?: Identity.ProviderLink[] },
    ctx: TenantContext = {},
  ): Promise<Identity.IIdentity<Profile>> {
    if (input.profile !== undefined) this._assertProfileWithinCap(input.profile)
    const created = await this._store.create(
      {
        providers: input.providers ?? [],
        ...(input.profile !== undefined && { profile: input.profile }),
        ...(input.tenantId !== undefined && { tenantId: input.tenantId }),
      },
      ctx,
    )
    await this._events.emit('signup.completed', { identity: created })
    return created
  }

  async updateProfile(
    id: string,
    profilePatch: Partial<Profile>,
    expectedVersion: number,
    ctx: TenantContext = {},
  ): Promise<Identity.IIdentity<Profile>> {
    const cur = await this._store.findById(id, ctx)
    if (!cur) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
    const nextProfile = { ...(cur.profile ?? {}), ...profilePatch } as Profile
    this._assertProfileWithinCap(nextProfile)
    return this._store.update(id, { profile: nextProfile }, expectedVersion, ctx)
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
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'identity profile is not JSON-serializable',
      })
    }
    if (bytes > cap) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: `identity profile exceeds size cap (${bytes} > ${cap} bytes)`,
      })
    }
  }

  // --- provider linking ------------------------------------------------

  async link(identityId: string, link: Omit<Identity.ProviderLink, 'addedAt'>, ctx: TenantContext = {}): Promise<void> {
    const cur = await this._store.findById(identityId, ctx)
    if (!cur) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
    // Reject duplicate provider link for same identity.
    if (cur.providers.some((p) => p.providerId === link.providerId)) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId: link.providerId,
        detail: 'already linked',
      })
    }
    await this._store.link(identityId, { ...link, addedAt: Date.now() }, ctx)
    await this._events.emit('identity.linked', { identityId, providerId: link.providerId })
  }

  async unlink(identityId: string, providerId: string, ctx: TenantContext = {}): Promise<void> {
    const cur = await this._store.findById(identityId, ctx)
    if (!cur) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
    // Don't allow unlinking the last credential surface - leaves account inaccessible.
    if (cur.providers.length <= 1) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId,
        detail: 'cannot unlink last provider; add another method first',
      })
    }
    await this._store.unlink(identityId, providerId, ctx)
  }

  async merge(survivorId: string, dupId: string, ctx: TenantContext = {}): Promise<void> {
    if (survivorId === dupId) {
      throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
        providerId: 'merge',
        detail: 'survivor and dup are the same identity',
      })
    }
    await this._store.merge(survivorId, dupId, ctx)
    await this._events.emit('identity.merged', {
      survivorId,
      mergedFromId: dupId,
    })
  }

  // --- soft-delete / restore / erase ----------------------------------

  async softDelete(id: string, ctx: TenantContext = {}): Promise<void> {
    await this._store.softDelete(id, this._cfg.softDeleteGracePeriodMs, ctx)
  }

  async restore(id: string, ctx: TenantContext = {}): Promise<Identity.IIdentity<Profile>> {
    return this._store.restore(id, ctx)
  }

  /** Hard-erase. Audit-logged for compliance. Cannot be undone. */
  async erase(id: string, opts: { reason: string; operatorId?: string }, ctx: TenantContext = {}): Promise<void> {
    await this._store.erase(id, ctx)
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
      profile?: Profile
      tenantId?: string
      providers?: Identity.ProviderLink[]
    }>,
    opts: { mode?: 'skipExisting' | 'merge' | 'replace' } = {},
    ctx: TenantContext = {},
  ): Promise<{ created: number; skipped: number; failed: number }> {
    const mode = opts.mode ?? 'skipExisting'
    let created = 0
    let skipped = 0
    let failed = 0
    for (const row of rows) {
      try {
        // Cast-free extraction + case-fold for bulk-import dedup.
        const email = extractEmail(row.profile)
        const existing = email ? await this._store.findByEmail(email, ctx) : null
        if (existing && mode === 'skipExisting') {
          skipped++
          continue
        }
        if (existing && mode === 'merge') {
          // Link any new providers without duplicating; do not patch profile here.
          for (const link of row.providers ?? []) {
            if (!existing.providers.some((p) => p.providerId === link.providerId)) {
              await this._store.link(existing.id, link, ctx)
            }
          }
          skipped++
          continue
        }
        if (existing && mode === 'replace') {
          await this._store.erase(existing.id, ctx)
        }
        await this.create(row, ctx)
        created++
      } catch {
        failed++
      }
    }
    return { created, skipped, failed }
  }

  // --- GDPR export ------------------------------------------------------

  /**
   * Portable export under GDPR right-to-access. Argon2id secrets, OAuth
   * tokens, recovery code hashes, and other credential `secret` fields are
   * always stripped. Sessions are exported separately by Sessions facet if
   * the consumer wants them.
   */
  async exportAll(
    id: string,
    credentials: Credential.IStore,
    ctx: TenantContext = {},
    opts: { sessions?: Session.IStore } = {},
  ): Promise<IdentitiesFacet.IExportBlob<Profile>> {
    const identity = await this._store.findById(id, ctx)
    if (!identity) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
    const creds = await credentials.listByIdentity(id, undefined, ctx)
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
  static exportToJson<P>(blob: IdentitiesFacet.IExportBlob<P>): string {
    return JSON.stringify(blob, sortKeys, 2)
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/**
 * Normalize an email extracted from a caller-supplied Profile.
 * Delegates the raw cast-free extraction to `getProfileString` from
 * `credential-utils`; this wrapper adds the trim + lowercase that the
 * dedup-by-email lookup requires.
 */
function extractEmail(profile: unknown): string | undefined {
  const raw = getProfileString(profile, 'email')
  if (raw === undefined) return undefined
  const trimmed = raw.trim().toLowerCase()
  return trimmed.length > 0 ? trimmed : undefined
}

function sortKeys(_key: string, value: unknown): unknown {
  if (isPlainObject(value)) {
    const sorted: Record<string, unknown> = {}
    for (const k of Object.keys(value).sort()) {
      sorted[k] = value[k]
    }
    return sorted
  }
  return value
}

/**
 * Namespace merge for IdentitiesFacet. Co-locates the config + input + output
 * shapes alongside the class via TS class+namespace merging.
 */
export namespace IdentitiesFacet {
  export interface IConfig {
    /** Grace before hard-purge after softDelete. Default 7 days. */
    softDeleteGracePeriodMs: number
    /**
     * maximum serialized (JSON / UTF-8 bytes) size of a profile.
     * Defaults to 16 KiB. Set to `0` to disable (not recommended -
     * unbounded profiles are a storage / read-amplification DoS).
     */
    profileMaxBytes?: number
  }

  export interface IExportBlob<Profile> {
    identity: Identity.IIdentity<Profile>
    credentials: Array<Omit<Credential.ICredential, 'secret'>>
    /** Live + recently-revoked sessions. Empty when caller skips sessions store. */
    sessions: Array<Omit<Session.ISession, 'csrfHash'>>
    /** GDPR Article 20 envelope: schema version + export timestamp. */
    schemaVersion: '1'
    exportedAt: number
  }
}
