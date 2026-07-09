import { getProfileString } from '../credential-utils'
import { AuthError } from '../errors'
import type { Session } from '../sessions/sessions.types'
import type { Credential } from '../types/identity'
import type { TenantContext } from '../types/infra'
import type { Events } from '../types/provider'
import { DEFAULT_IDENTITIES_CONFIG } from './identities.constants'
import type { Identity } from './identities.types'

/**
 * Identities facet - CRUD + linking + merging + GDPR primitives.
 * Optimistic locking discipline: every write that mutates `Identity` flows
 * through `update(expectedVersion)`; callers that pass a stale version see
 * `AUTH/STALE_WRITE` and decide retry/surface.
 */
export class IdentitiesFacet<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase> {
  constructor(
    private readonly _store: Identity.Store<Profile>,
    private readonly _events: Events.IBus,
    private readonly _cfg: Identity.Config = DEFAULT_IDENTITIES_CONFIG,
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

  async getById(id: string): Promise<Identity.Me<Profile> | null> {
    return this._store.findById(id)
  }

  async getByEmail(email: string): Promise<Identity.Me<Profile> | null> {
    // RFC 5321 cap + typeof guard: prevents multi-MB lookups + non-string crashes
    // before reaching adapter.
    if (typeof email !== 'string' || email.length === 0 || email.length > 254) return null
    return this._store.findByEmail(email.trim().toLowerCase())
  }

  async getByProviderSub(providerId: string, sub: string): Promise<Identity.Me<Profile> | null> {
    // Defensive caps; both keys flow into SQL `=`-comparisons + JSONB extracts.
    if (typeof providerId !== 'string' || providerId.length === 0 || providerId.length > 128) return null
    if (typeof sub !== 'string' || sub.length === 0 || sub.length > 512) return null
    return this._store.findByProviderSub(providerId, sub)
  }

  // --- create / update --------------------------------------------------

  async create(input: {
    profile: Profile
    tenantId?: string
    providers?: Identity.ProviderLink[]
    emailVerified?: boolean
  }): Promise<Identity.Me<Profile>> {
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
  ): Promise<Identity.Me<Profile>> {
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

  async link(identityId: string, link: Omit<Identity.ProviderLink, 'addedAt'>): Promise<void> {
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

  async restore(id: string): Promise<Identity.Me<Profile>> {
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
      providers?: Identity.ProviderLink[]
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
    opts: { sessions?: Session.Store } = {},
  ): Promise<Identity.ExportBlob<Profile>> {
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
  static exportToJson<P extends Identity.ProfileMetadataBase>(blob: Identity.ExportBlob<P>): string {
    return JSON.stringify(blob, sortKeys, 2)
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** Trim + lowercase the `email` field off a profile; `undefined` when absent or non-string. */
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
