import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../../core/types'
import { parsePolicyRow, parseRoleRow, validatePolicy, validateRole } from '../../core/validate'
import { iamAssertAttributesParam } from '../../shared/attributes'

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
    onPolicyError?: (err: Error, ctx: { adapter: 'redis'; rowId: string }) => void
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
  private _onPolicyError?: (err: Error, ctx: { adapter: 'redis'; rowId: string }) => void
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

  /**
   * Creates a new Redis-backed adapter.
   *
   * @param config - Provides the client and optional key prefix.
   */
  constructor(config: IamRedis.IConfig<TClient>) {
    this._client = config.client
    this._prefix = config.keyPrefix ?? ''
    this._onPolicyError = config.onPolicyError
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
      this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), rowId)
      return null
    }
    const policy = parsePolicyRow<TAction, TResource, TRole>(parsed)
    if (policy === null) {
      const issues = validatePolicy(parsed)
        .issues.map((i) => i.message)
        .join('; ')
      this._reportPolicyError(new Error(`Invalid policy "${rowId}": ${issues}`), rowId)
      return null
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
   * space as separator. Format: exactly one `0x20`, no `0x00` byte. On read,
   * such entries are transparently re-encoded with the NUL separator and the
   * legacy form is removed from the set.
   *
   * False positives are scoped to subjects whose role/scope strings happened
   * to contain spaces - exactly the cases that were silently broken before -
   * so the migration corrects rather than corrupts them.
   */
  private _isLegacyEncoded(member: string): boolean {
    if (member.includes(IamRedisAdapter._SEP)) return false
    const first = member.indexOf(' ')
    if (first === -1) return false
    return member.indexOf(' ', first + 1) === -1
  }

  private _encodeAssignment(roleId: TRole, scope?: TScope | null): string {
    const r = roleId as string
    const s = (scope ?? '') as string
    if (r.includes(IamRedisAdapter._SEP) || s.includes(IamRedisAdapter._SEP)) {
      throw new Error('[@gentleduck/iam:redis] role / scope must not contain NUL bytes')
    }
    return `${r}${IamRedisAdapter._SEP}${s}`
  }
  private _decodeAssignment(member: string): { role: TRole; scope?: TScope } {
    const sep = member.indexOf(IamRedisAdapter._SEP)
    if (sep === -1) {
      // Legacy-format fallback: older versions used a space separator.
      // Accept exactly-one-space entries here; the caller
      // (`_migrateLegacyAssignment`) re-encodes them on first read.
      if (this._isLegacyEncoded(member)) {
        const legacySep = member.indexOf(' ')
        const role = member.slice(0, legacySep) as TRole
        const scope = member.slice(legacySep + 1)
        return scope === '' ? { role } : { role, scope: scope as TScope }
      }
      return { role: member as TRole }
    }
    const role = member.slice(0, sep) as TRole
    const scope = member.slice(sep + 1)
    return scope === '' ? { role } : { role, scope: scope as TScope }
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
    await this._client.hset(this._policiesKey(), p.id, JSON.stringify(p))
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
    await this._client.hset(this._rolesKey(), r.id, JSON.stringify(r))
  }

  /**
   * Removes a role by ID.
   *
   * @param id - Identifies the role to delete.
   * @returns Resolves once the HDEL completes.
   */
  async deleteRole(id: string): Promise<void> {
    await this._client.hdel(this._rolesKey(), id)
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
   * @param subjectId - Identifies the subject receiving the role.
   * @param roleId - Specifies the role being granted.
   * @param scope - Optional scope binding the assignment.
   * @returns Resolves once the SADD completes.
   */
  async assignRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void> {
    const key = this._assignmentsKey(subjectId)
    // Serialise against the migration path.
    await this._runSerialised(key, () => this._client.sadd(key, this._encodeAssignment(roleId, scope)))
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
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      this._reportPolicyError(new Error(`Attributes for "${subjectId}" must be a JSON object`), subjectId)
      throw new Error(`[@gentleduck/iam:redis] corrupted attributes for "${subjectId}" (not a JSON object)`)
    }
    return parsed as IamPrimitives.Attributes
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

/** Factory around {@link IamRedisAdapter}, for callers who prefer functions to `new`. */
export function iamRedisAdapter(...args: ConstructorParameters<typeof IamRedisAdapter>): IamRedisAdapter {
  return new IamRedisAdapter(...args)
}
