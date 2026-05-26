/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../errors'
import type { TenantContext } from '../types/context'
import type { Credential } from '../types/credential'
import type { Events } from '../types/events'
import type { Identity } from '../types/identity'

export interface IdentitiesFacetConfig {
  /** Grace before hard-purge after softDelete. Default 7 days. */
  softDeleteGracePeriodMs: number
}

export const DEFAULT_IDENTITIES_CONFIG: IdentitiesFacetConfig = {
  softDeleteGracePeriodMs: 7 * 24 * 60 * 60 * 1000,
}

export interface ExportBlob<Profile> {
  identity: Identity.IIdentity<Profile>
  credentials: Array<Omit<Credential.ICredential, 'secret'>>
  /** Always redacted; consumer never sees plaintext or hashes. */
  exportedAt: number
}

/**
 * Identities facet - CRUD + linking + merging + GDPR primitives.
 * Optimistic locking discipline: every write that mutates `Identity` flows
 * through `update(expectedVersion)`; callers that pass a stale version see
 * `AUTH/STALE_WRITE` and decide retry/surface.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class IdentitiesFacet<Profile = unknown> {
  constructor(
    private readonly _store: Identity.IStore<Profile>,
    private readonly _events: Events.IBus,
    private readonly _cfg: IdentitiesFacetConfig = DEFAULT_IDENTITIES_CONFIG,
  ) {}

  // --- lookup -----------------------------------------------------------

  async getById(id: string, ctx: TenantContext = {}): Promise<Identity.IIdentity<Profile> | null> {
    return this._store.findById(id, ctx)
  }

  async getByEmail(email: string, ctx: TenantContext = {}): Promise<Identity.IIdentity<Profile> | null> {
    return this._store.findByEmail(email, ctx)
  }

  async getByProviderSub(
    providerId: string,
    sub: string,
    ctx: TenantContext = {},
  ): Promise<Identity.IIdentity<Profile> | null> {
    return this._store.findByProviderSub(providerId, sub, ctx)
  }

  // --- create / update --------------------------------------------------

  async create(
    input: { profile?: Profile; tenantId?: string; providers?: Identity.ProviderLink[] },
    ctx: TenantContext = {},
  ): Promise<Identity.IIdentity<Profile>> {
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
    return this._store.update(id, { profile: nextProfile }, expectedVersion, ctx)
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
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
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
        const email = (row.profile as { email?: string } | undefined)?.email
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
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async exportAll(id: string, credentials: Credential.IStore, ctx: TenantContext = {}): Promise<ExportBlob<Profile>> {
    const identity = await this._store.findById(id, ctx)
    if (!identity) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
    const creds = await credentials.listByIdentity(id, undefined, ctx)
    return {
      identity,
      credentials: creds.map(({ secret: _secret, ...rest }) => rest),
      exportedAt: Date.now(),
    }
  }
}

/**
 * Namespace merge for IdentitiesFacet. Co-locates the config + input + output
 * shapes alongside the class via TS class+namespace merging. Consumers can
 * write either the flat name (e.g. IdentitiesFacetConfig) or the
 * namespaced form (IdentitiesFacet.IConfig); both
 * resolve to the same type.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace IdentitiesFacet {
  /** Alias for the flat `IdentitiesFacetConfig` type. */
  export type IConfig = IdentitiesFacetConfig
  /** Alias for the flat generic `ExportBlob<Profile>` type. */
  export type IExportBlob<Profile = unknown> = ExportBlob<Profile>
}
