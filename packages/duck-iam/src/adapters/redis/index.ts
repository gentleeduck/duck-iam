import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../../core/types'
import { parsePolicyRow, parseRoleRow, validatePolicy, validateRole } from '../../core/validate'
import { iamAssertNoAssignOptions } from '../../shared/assign-options'
import { iamAssertRoleExists } from '../../shared/assignment-target'
import { iamAssertAttributesParam, iamNarrowAttributes } from '../../shared/attributes'
import {
  iamAssertSavablePolicy,
  iamAssertSavableRole,
  iamNormalizePolicy,
  iamUnreadablePolicy,
} from '../../shared/rows'
import { iamAssertAssignableScope } from '../../shared/scope'
import { iamAsRoleLiteral, iamAsScopeLiteral } from '../../shared/tenant-literals'

/** Redis adapter integration types. Type-only namespace - zero bundle cost. */
export namespace IamRedis {
  /**
   * Describes the minimal Redis client surface used by {@link IamRedisAdapter}.
   *
   * Both ioredis and node-redis (v4+) implement these methods, so consumers can
   * pass either without a hard dependency.
   */
  export interface ILike {
    get(key: string): Promise<string | null>
    set(key: string, value: string): Promise<unknown>
    del(...keys: string[]): Promise<number>
    hset(key: string, field: string, value: string): Promise<number>
    hget(key: string, field: string): Promise<string | null>
    hdel(key: string, ...fields: string[]): Promise<number>
    hkeys(key: string): Promise<string[]>
    hvals(key: string): Promise<string[]>
    hgetall(key: string): Promise<Record<string, string>>
    sadd(key: string, ...members: string[]): Promise<number>
    srem(key: string, ...members: string[]): Promise<number>
    smembers(key: string): Promise<string[]>
    /** Optional Lua EVAL for cross-process atomic RMW on assignments; targets ioredis positional shape. */
    eval?(script: string, numkeys: number, ...keysAndArgs: string[]): Promise<unknown>
    /**
     * Optional key listing, used only by `deleteRole` to find the grants that
     * named the deleted role. ioredis and node-redis both spell it
     * `keys(pattern): Promise<string[]>`, unlike `SCAN`, whose cursor and
     * options differ between the two. Without it `deleteRole` cannot reach the
     * assignment sets and says so through `onPolicyError` rather than leaving
     * the orphans unmentioned.
     */
    keys?(pattern: string): Promise<string[]>
  }

  /** Describes the configuration required to construct a {@link IamRedisAdapter}. */
  export interface IConfig<TClient extends ILike = ILike> {
    /** Provides the Redis client instance (ioredis, node-redis v4+, or compatible). */
    client: TClient
    /** Optional key prefix that namespaces every duck-iam key. */
    keyPrefix?: string
    /**
     * Invoked when a stored row fails JSON parse or shape validation. The
     * malformed row is dropped from the result set; the rest are returned
     * intact. Wire this to your alerting pipeline so corrupt rows do not
     * silently vanish from authorization decisions.
     */
    onPolicyError?: IamAdapter.RowErrorHandler<'redis'>
    /**
     * Opts in to rewriting legacy space-separated assignment members into the
     * current NUL-separated form on read. Off by default: the legacy shape is
     * a heuristic, not a format, so a *global* grant of a role whose id
     * contains a space is indistinguishable from a scoped grant of the prefix
     * before it. Enable only when every member of every assignments set was
     * written by an older version of this adapter.
     */
    migrateLegacyAssignments?: boolean
  }
}

/**
 * Redis-backed adapter using hashes + sets. Layout (with `keyPrefix`):
 * `${p}policies` (hash), `${p}roles` (hash), `${p}assignments:${id}` (set: `roleId\x00scope`), `${p}attrs:${id}` (JSON).
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 */
export class IamRedisAdapter<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
  TClient extends IamRedis.ILike = IamRedis.ILike,
> implements IamAdapter.IAdapter<TAction, TResource, TRole, TScope>
{
  private _client: TClient
  private _prefix: string
  private _onPolicyError?: IamAdapter.RowErrorHandler<'redis'>
  /**
   * Per-assignment-key serialisation. Read-modify-write on the legacy
   * migration path can race with concurrent `revokeRole` and resurrect a
   * just-deleted assignment. Without `EVAL`/`MULTI` in the minimal
   * `IamRedis.ILike` interface, the soundest in-process fix is to serialise
   * writes against a single assignments key behind a chained promise.
   * Cross-process races remain - operators running multiple writer
   * processes should rely on the Lua `eval` path when available.
   */
  private _assignmentWriteLocks = new Map<string, Promise<unknown>>()
  private _migrateLegacyAssignments: boolean

  /**
   * Creates a new Redis-backed adapter.
   *
   * @param config - Provides the client and optional key prefix.
   */
  constructor(config: IamRedis.IConfig<TClient>) {
    this._client = config.client
    this._prefix = config.keyPrefix ?? ''
    this._onPolicyError = config.onPolicyError
    this._migrateLegacyAssignments = config.migrateLegacyAssignments ?? false
  }

  /**
   * Parse + validate a stored JSON blob. Returns `null` on parse error or
   * shape mismatch and routes the failure through `onPolicyError` (or the
   * console as a last resort) so the malformed row never reaches the engine.
   */
  private _safeParsePolicy(raw: string, rowId: string): AccessControl.IPolicy<TAction, TResource, TRole> | null {
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch (err) {
      const detail = err instanceof Error ? err : new Error(String(err))
      this._reportPolicyError(detail, rowId)
      throw iamUnreadablePolicy('redis', rowId, detail.message)
    }
    const policy = parsePolicyRow<TAction, TResource, TRole>(parsed)
    if (policy === null) {
      const issues = validatePolicy(parsed)
        .issues.map((i) => i.message)
        .join('; ')
      this._reportPolicyError(new Error(`Invalid policy "${rowId}": ${issues}`), rowId)
      throw iamUnreadablePolicy('redis', rowId, issues)
    }
    return policy
  }

  private _safeParseRole(raw: string, rowId: string): AccessControl.IRole<TAction, TResource, TRole, TScope> | null {
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch (err) {
      this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), rowId)
      return null
    }
    const role = parseRoleRow<TAction, TResource, TRole, TScope>(parsed)
    if (role === null) {
      const issues = validateRole(parsed)
        .issues.map((i) => i.message)
        .join('; ')
      this._reportPolicyError(new Error(`Invalid role "${rowId}": ${issues}`), rowId)
      return null
    }
    return role
  }

  private _reportPolicyError(err: Error, rowId: string): void {
    if (this._onPolicyError) {
      this._onPolicyError(err, { adapter: 'redis', rowId })
      return
    }
    console.warn(`[@gentleduck/iam:redis] dropped malformed row "${rowId}": ${err.message}`)
  }

  private _policiesKey(): string {
    return `${this._prefix}policies`
  }
  private _rolesKey(): string {
    return `${this._prefix}roles`
  }
  private _assignmentsKey(subjectId: string): string {
    return `${this._prefix}assignments:${subjectId}`
  }
  private _attrsKey(subjectId: string): string {
    return `${this._prefix}attrs:${subjectId}`
  }

  /**
   * Separator between role and scope in an encoded assignment set member.
   *
   * NUL (`0x00`) is rejected at encode time so it cannot appear in any
   * `TRole` / `TScope` string, preventing decode collisions that would drift
   * privileges (e.g. a space-separated `'admin user'` round-tripping as
   * `('admin', 'user ')`).
   */
  private static readonly _SEP = '\0'

  /**
   * Detects entries written by versions of this adapter that used a literal
   * space as separator. Format: exactly one `0x20`, no `0x00` byte.
   *
   * "One space" is a guess, not a format. A member holding a *global* grant of
   * a role whose id contains a space reads identically to a scoped grant of
   * the prefix before that space, so treating it as legacy would grant a role
   * the subject never held and then destroy the original by rewriting the set.
   * Nothing here can tell the two apart, so the reinterpretation is off unless
   * the operator opts in with `migrateLegacyAssignments`.
   */
  private _isLegacyEncoded(member: string): boolean {
    if (!this._migrateLegacyAssignments) return false
    if (member.includes(IamRedisAdapter._SEP)) return false
    const first = member.indexOf(' ')
    if (first === -1) return false
    return member.indexOf(' ', first + 1) === -1
  }

  private _encodeAssignment(roleId: TRole, scope?: TScope | null): string {
    const r: string = roleId
    // The empty string is how this encoding spells "no scope", so a literal
    // empty scope would decode as a global assignment: strictly more power than
    // was granted. `assignRole` / `revokeRole` already refuse it at the shared
    // boundary; this is the encoder's own guard, kept because every internal
    // caller of `_encodeAssignment` would otherwise have to remember.
    iamAssertAssignableScope('redis', scope, 'lookup')
    const s: string = scope ?? ''
    if (r.includes(IamRedisAdapter._SEP) || s.includes(IamRedisAdapter._SEP)) {
      throw new Error('[@gentleduck/iam:redis] role / scope must not contain NUL bytes')
    }
    return `${r}${IamRedisAdapter._SEP}${s}`
  }
  private _decodeAssignment(member: string): { role: TRole; scope?: TScope } {
    const sep = member.indexOf(IamRedisAdapter._SEP)
    if (sep === -1) {
      // Legacy-format fallback, only under `migrateLegacyAssignments`: older
      // versions used a space separator. The caller
      // (`_migrateLegacyAssignment`) re-encodes these on first read.
      if (this._isLegacyEncoded(member)) {
        const legacySep = member.indexOf(' ')
        const role = iamAsRoleLiteral<TRole>(member.slice(0, legacySep))
        const scope = member.slice(legacySep + 1)
        return scope === '' ? { role } : { role, scope: iamAsScopeLiteral<TScope>(scope) }
      }
      return { role: iamAsRoleLiteral<TRole>(member) }
    }
    const role = iamAsRoleLiteral<TRole>(member.slice(0, sep))
    const scope = member.slice(sep + 1)
    return scope === '' ? { role } : { role, scope: iamAsScopeLiteral<TScope>(scope) }
  }

  /**
   * Serialise an async task against a specific assignments key. Chains onto
   * any in-flight task for the same key so concurrent callers see a strict
   * happens-before order, defeating the migrate-vs-revoke race in a
   * single-process deployment.
   */
  private _runSerialised<T>(key: string, task: () => Promise<T>): Promise<T> {
    const prev = this._assignmentWriteLocks.get(key) ?? Promise.resolve()
    const next = prev.then(task, task)
    // Tail swallows the rejection only on the chain copy; caller owns `next`'s.
    const tail = next.then(
      () => undefined,
      () => undefined,
    )
    const settled = tail.finally(() => {
      if (this._assignmentWriteLocks.get(key) === settled) this._assignmentWriteLocks.delete(key)
    })
    this._assignmentWriteLocks.set(key, settled)
    return next
  }

  /**
   * One-shot migration: convert any legacy space-separated assignment members
   * for `subjectId` to the NUL-separated form. Idempotent and best-effort -
   * a migration failure must not block authorization, so any errors are
   * surfaced through `_reportPolicyError` and the original entries left in
   * place to be retried on the next read.
   */
  private async _migrateLegacyAssignment(subjectId: string, members: string[]): Promise<void> {
    const legacy = members.filter((m) => this._isLegacyEncoded(m))
    if (legacy.length === 0) return
    const key = this._assignmentsKey(subjectId)
    // Prefer Lua EVAL for true atomicity (cross-process safe).
    // Falls back to in-process serialisation when client lacks eval.
    if (typeof this._client.eval === 'function') {
      await this._migrateLegacyAssignmentLua(key, subjectId, legacy)
      return
    }
    // Single-process serialisation fallback.
    await this._runSerialised(key, async () => {
      try {
        const current = await this._client.smembers(key)
        const stillLegacy = current.filter((m) => this._isLegacyEncoded(m))
        if (stillLegacy.length === 0) return
        const reEncoded: string[] = []
        for (const m of stillLegacy) {
          const decoded = this._decodeAssignment(m)
          reEncoded.push(this._encodeAssignment(decoded.role, decoded.scope))
        }
        await this._client.sadd(key, ...reEncoded)
        await this._client.srem(key, ...stillLegacy)
      } catch (err) {
        this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), `assignments:${subjectId}`)
      }
    })
  }

  /** Cross-process atomic legacy-assignment migration via Redis EVAL; ARGV pairs `[migrated, legacy]`. */
  private static readonly _MIGRATE_LUA = `
    local key = KEYS[1]
    for i = 1, #ARGV, 2 do
      local migrated = ARGV[i]
      local legacy = ARGV[i + 1]
      redis.call('SADD', key, migrated)
      redis.call('SREM', key, legacy)
    end
    return 'OK'
  `

  private async _migrateLegacyAssignmentLua(key: string, subjectId: string, legacy: string[]): Promise<void> {
    try {
      const args: string[] = []
      for (const m of legacy) {
        const decoded = this._decodeAssignment(m)
        args.push(this._encodeAssignment(decoded.role, decoded.scope))
        args.push(m)
      }
      const evalFn = this._client.eval
      if (!evalFn) return
      await evalFn.call(this._client, IamRedisAdapter._MIGRATE_LUA, 1, key, ...args)
    } catch (err) {
      this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), `assignments:${subjectId}`)
    }
  }

  /**
   * Lists every policy stored in the Redis hash.
   *
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns All policies decoded from the `policies` hash.
   */
  async listPolicies(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IPolicy<TAction, TResource, TRole>[]> {
    const entries = await this._client.hgetall(this._policiesKey())
    const out: AccessControl.IPolicy<TAction, TResource, TRole>[] = []
    for (const [rowId, raw] of Object.entries(entries)) {
      const parsed = this._safeParsePolicy(raw, rowId)
      if (parsed) out.push(parsed)
    }
    return out
  }

  /**
   * Fetches a single policy by ID.
   *
   * @param id - Identifies the policy to look up.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns The matching policy or `null` when absent.
   */
  async getPolicy(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IPolicy<TAction, TResource, TRole> | null> {
    const value = await this._client.hget(this._policiesKey(), id)
    return value ? this._safeParsePolicy(value, id) : null
  }

  /**
   * Stores or overwrites a policy under its ID.
   *
   * @param p - Provides the policy to persist.
   * @returns Resolves once the HSET completes.
   */
  async savePolicy(p: AccessControl.IPolicy<TAction, TResource, TRole>): Promise<void> {
    iamAssertSavablePolicy('redis', p)
    await this._client.hset(this._policiesKey(), p.id, JSON.stringify(iamNormalizePolicy(p)))
  }

  /**
   * Removes a policy by ID.
   *
   * @param id - Identifies the policy to delete.
   * @returns Resolves once the HDEL completes.
   */
  async deletePolicy(id: string): Promise<void> {
    await this._client.hdel(this._policiesKey(), id)
  }

  /**
   * Lists every role stored in the Redis hash.
   *
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns All roles decoded from the `roles` hash.
   */
  async listRoles(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope>[]> {
    const entries = await this._client.hgetall(this._rolesKey())
    const out: AccessControl.IRole<TAction, TResource, TRole, TScope>[] = []
    for (const [rowId, raw] of Object.entries(entries)) {
      const parsed = this._safeParseRole(raw, rowId)
      if (parsed) out.push(parsed)
    }
    return out
  }

  /**
   * Fetches a single role by ID.
   *
   * @param id - Identifies the role to look up.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns The matching role or `null` when absent.
   */
  async getRole(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope> | null> {
    const value = await this._client.hget(this._rolesKey(), id)
    return value ? this._safeParseRole(value, id) : null
  }

  /**
   * Stores or overwrites a role under its ID.
   *
   * @param r - Provides the role to persist.
   * @returns Resolves once the HSET completes.
   */
  async saveRole(r: AccessControl.IRole<TAction, TResource, TRole, TScope>): Promise<void> {
    iamAssertSavableRole('redis', r)
    await this._client.hset(this._rolesKey(), r.id, JSON.stringify(r))
  }

  /**
   * Removes a role by ID, and with it every grant that named it.
   *
   * The grants go too because the SQL schemas take them: `fk_iam_assignments_role`
   * is `ON DELETE CASCADE`, so `deleteRole('editor')` left `getSubjectRoles`
   * returning `editor` here and `[]` on drizzle and prisma - one call, two
   * answers. Keeping the orphan is not the harmless option either: it reads as
   * a grant, `assignRole` now refuses to create one like it, and recreating a
   * role under the reused id hands it back to everyone who once held it,
   * without an operator granting anything.
   *
   * This is the one operation that touches the whole assignment keyspace, so it
   * costs a `KEYS` sweep. It is an admin-rate call - deleting a role is not on
   * any request path - and the alternative, a reverse index, would cascade only
   * for grants written after the index existed and silently miss every older
   * one.
   *
   * @param id - Identifies the role to delete.
   * @returns Resolves once the role and its grants are removed.
   */
  async deleteRole(id: string): Promise<void> {
    await this._client.hdel(this._rolesKey(), id)
    await this._revokeEverywhere(id)
  }

  /**
   * Drops every assignment naming `roleId`, scoped and global alike.
   *
   * Each key's rewrite goes through {@link _runSerialised} for the same reason
   * the migration path does: the members are read, filtered and removed in
   * separate commands, and a concurrent `assignRole` on that subject must not
   * land between the read and the `SREM`.
   */
  private async _revokeEverywhere(roleId: string): Promise<void> {
    const list = this._client.keys
    if (list === undefined) {
      this._reportPolicyError(
        new Error(
          'the role was deleted but its grants were not: this client exposes no `keys`, ' +
            'so the assignment sets cannot be enumerated. Revoke them explicitly, or pass a ' +
            'client (ioredis, node-redis v4+) that implements it.',
        ),
        `roles:${roleId}`,
      )
      return
    }
    const keys = await list.call(this._client, `${globLiteral(this._prefix)}assignments:*`)
    for (const key of keys) {
      await this._runSerialised(key, async () => {
        const stale = (await this._client.smembers(key)).filter((m) => this._decodeAssignment(m).role === roleId)
        if (stale.length === 0) return
        await this._client.srem(key, ...stale)
      })
    }
  }

  /**
   * Lists deduplicated role IDs assigned to a subject.
   *
   * @param subjectId - Identifies the subject whose roles are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns Deduplicated array of role IDs.
   */
  async getSubjectRoles(subjectId: string, _opts?: IamAdapter.IReadOptions): Promise<TRole[]> {
    const members = await this._client.smembers(this._assignmentsKey(subjectId))
    const roles = new Set<TRole>()
    for (const m of members) {
      const decoded = this._decodeAssignment(m)
      // Contract: unscoped (global) roles only - same as file/memory
      // adapters. Scoped assignments are surfaced via getSubjectScopedRoles.
      if (decoded.scope !== undefined) continue
      roles.add(decoded.role)
    }
    await this._migrateLegacyAssignment(subjectId, members)
    return Array.from(roles)
  }

  /**
   * Lists scoped role assignments for a subject (excludes unscoped).
   *
   * @param subjectId - Identifies the subject whose scoped roles are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns Array of `(role, scope)` pairs.
   */
  async getSubjectScopedRoles(
    subjectId: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<IamRequest.IScopedRole<TRole, TScope>[]> {
    const members = await this._client.smembers(this._assignmentsKey(subjectId))
    const out: IamRequest.IScopedRole<TRole, TScope>[] = []
    for (const m of members) {
      const decoded = this._decodeAssignment(m)
      if (decoded.scope !== undefined) out.push({ role: decoded.role, scope: decoded.scope })
    }
    await this._migrateLegacyAssignment(subjectId, members)
    return out
  }

  /**
   * Grants a role to a subject, optionally restricted to a scope.
   *
   * Idempotent thanks to Redis set semantics.
   *
   * A role that is not stored is refused - see {@link iamAssertRoleExists}.
   *
   * @param subjectId - Identifies the subject receiving the role.
   * @param roleId - Specifies the role being granted.
   * @param scope - Optional scope binding the assignment.
   * @returns Resolves once the SADD completes.
   */
  async assignRole(subjectId: string, roleId: TRole, scope?: TScope, opts?: IamAdapter.IAssignOptions): Promise<void> {
    iamAssertAssignableScope('redis', scope)
    iamAssertNoAssignOptions('redis', opts)
    // Encode before the lookup: an id this encoding cannot carry is refused for
    // that reason, rather than reported as a missing role after a wasted round
    // trip.
    const member = this._encodeAssignment(roleId, scope)
    // One extra round trip per grant, and `hget` rather than `hexists` so the
    // operator-supplied client interface does not have to grow a method.
    iamAssertRoleExists('redis', (await this._client.hget(this._rolesKey(), roleId)) !== null)
    const key = this._assignmentsKey(subjectId)
    // Serialise against the migration path.
    await this._runSerialised(key, () => this._client.sadd(key, member))
  }

  /**
   * Removes role assignments matching the given filters.
   *
   * Omitting `scope` removes every assignment for the role regardless of scope.
   *
   * @param subjectId - Identifies the subject losing the role.
   * @param roleId - Specifies the role being revoked.
   * @param scope - Optional scope filter to narrow the delete.
   * @returns Resolves once the SREM completes.
   */
  async revokeRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void> {
    iamAssertAssignableScope('redis', scope, 'lookup')
    const key = this._assignmentsKey(subjectId)
    // Serialise against migration so a racing _migrateLegacyAssignment
    // cannot SADD the migrated form after our SREM lands.
    await this._runSerialised(key, async () => {
      if (scope !== undefined) {
        // Cover BOTH encodings so a partially-migrated set is cleaned in one go.
        const migrated = this._encodeAssignment(roleId, scope)
        const legacy = `${roleId} ${scope}`
        await this._client.srem(key, migrated, legacy)
        return
      }
      const members = await this._client.smembers(key)
      const targets = members.filter((m) => this._decodeAssignment(m).role === roleId)
      if (targets.length > 0) {
        await this._client.srem(key, ...targets)
      }
    })
  }

  /**
   * Fetches the attribute bag stored for a subject.
   *
   * @param subjectId - Identifies the subject whose attributes are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns The subject's attributes or `{}` when none are recorded.
   */
  async getSubjectAttributes(subjectId: string, _opts?: IamAdapter.IReadOptions): Promise<IamPrimitives.Attributes> {
    const value = await this._client.get(this._attrsKey(subjectId))
    if (!value) return {}
    let parsed: unknown
    try {
      parsed = JSON.parse(value)
    } catch (err) {
      // Corruption != empty; returning {} would silently strip ABAC and flip allow->deny.
      this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), subjectId)
      throw new Error(`[@gentleduck/iam:redis] corrupted attributes for "${subjectId}" (JSON parse failed)`)
    }
    const attrs = iamNarrowAttributes(parsed)
    if (attrs === null) {
      this._reportPolicyError(
        new Error(`Attributes for "${subjectId}" must be a JSON object of scalar values`),
        subjectId,
      )
      throw new Error(`[@gentleduck/iam:redis] corrupted attributes for "${subjectId}" (not a JSON object)`)
    }
    return attrs
  }

  /**
   * Shallow-merges new attributes into the subject's existing bag.
   *
   * @param subjectId - Identifies the subject whose attributes are written.
   * @param attrs - Provides the partial attribute patch to merge in.
   * @returns Resolves once the SET completes.
   */
  async setSubjectAttributes(subjectId: string, attrs: IamPrimitives.Attributes): Promise<void> {
    iamAssertAttributesParam('redis', subjectId, attrs)
    // Admin write path is the one place a corrupt existing blob must NOT
    // lock the operator out of recovering. Treat corrupt as `{}` and log
    // through _reportPolicyError so the operator still sees the signal.
    let existing: IamPrimitives.Attributes
    try {
      existing = await this.getSubjectAttributes(subjectId)
    } catch (err) {
      this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), subjectId)
      existing = {}
    }
    const merged = { ...existing, ...attrs }
    await this._client.set(this._attrsKey(subjectId), JSON.stringify(merged))
  }
}

/**
 * Escapes the glob metacharacters Redis's `KEYS` understands, so a key prefix
 * is matched as the literal text it is.
 *
 * `keyPrefix` is free text an operator chooses, and the only place it meets a
 * pattern is the `deleteRole` sweep. A prefix of `app[1]:` interpolated raw
 * turns `[1]` into a character class: the sweep then misses every key it owns -
 * cascading nothing, silently - and matches `app1:assignments:*`, a *different*
 * namespace, where it would remove that tenant's grants of the same role id.
 * Redis's matcher takes `\` as an escape, so every metacharacter is escaped and
 * the pattern means what the prefix says.
 */
function globLiteral(text: string): string {
  return text.replace(/[\\*?[\]]/g, (ch) => `\\${ch}`)
}

/** Factory around {@link IamRedisAdapter}, for callers who prefer functions to `new`. */
export function iamRedisAdapter(...args: ConstructorParameters<typeof IamRedisAdapter>): IamRedisAdapter {
  return new IamRedisAdapter(...args)
}
