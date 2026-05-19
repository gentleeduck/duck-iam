import type { AccessControl, Adapter, Primitives, Request } from '../../core/types'
import { validatePolicy, validateRole } from '../../core/validate'

/**
 * Redis adapter integration types. Type-only namespace - zero bundle cost.
 *
 * @author wildduck2 <https://github.com/wildduck2>
 */
export namespace Redis {
  /**
   * Describes the minimal Redis client surface used by {@link RedisAdapter}.
   *
   * Both ioredis and node-redis (v4+) implement these methods, so consumers can
   * pass either without a hard dependency.
   *
   * @author wildduck2 <https://github.com/wildduck2>
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
  }

  /**
   * Describes the configuration required to construct a {@link RedisAdapter}.
   *
   * @author wildduck2 <https://github.com/wildduck2>
   */
  export interface IConfig {
    /** Provides the Redis client instance (ioredis, node-redis v4+, or compatible). */
    client: ILike
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
 * @deprecated Use {@link Redis.ILike}. Will be removed in 3.0.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export type RedisLike = Redis.ILike

/**
 * @deprecated Use {@link Redis.IConfig}. Will be removed in 3.0.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export type RedisAdapterConfig = Redis.IConfig

/**
 * Persists the access store inside Redis using hashes and sets.
 *
 * Storage layout (with optional `keyPrefix`):
 * - `${prefix}policies` hash: policyId -> JSON(policy)
 * - `${prefix}roles` hash: roleId -> JSON(role)
 * - `${prefix}assignments:${id}` set: members are `roleId\0scope`
 * - `${prefix}attrs:${subjectId}` string: JSON(attributes)
 *
 * Suited to distributed deployments needing shared state. Pair with the
 * engine's LRU cache for hot reads.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @example
 * ```ts
 * import Redis from 'ioredis'
 * const adapter = new RedisAdapter({ client: new Redis(), keyPrefix: 'iam:' })
 * await adapter.savePolicy(policy)
 * ```
 * @author wildduck2 <https://github.com/wildduck2>
 */
export class RedisAdapter<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
> implements Adapter.IAdapter<TAction, TResource, TRole, TScope>
{
  private _client: Redis.ILike
  private _prefix: string
  private _onPolicyError?: (err: Error, ctx: { adapter: 'redis'; rowId: string }) => void

  /**
   * Creates a new Redis-backed adapter.
   *
   * @param config - Provides the client and optional key prefix.
   * @author wildduck2 <https://github.com/wildduck2>
   */
  constructor(config: Redis.IConfig) {
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
    const result = validatePolicy(parsed)
    if (!result.valid) {
      this._reportPolicyError(
        new Error(`Invalid policy "${rowId}": ${result.issues.map((i) => i.message).join('; ')}`),
        rowId,
      )
      return null
    }
    return parsed as AccessControl.IPolicy<TAction, TResource, TRole>
  }

  private _safeParseRole(raw: string, rowId: string): AccessControl.IRole<TAction, TResource, TRole, TScope> | null {
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch (err) {
      this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), rowId)
      return null
    }
    const result = validateRole(parsed)
    if (!result.valid) {
      this._reportPolicyError(
        new Error(`Invalid role "${rowId}": ${result.issues.map((i) => i.message).join('; ')}`),
        rowId,
      )
      return null
    }
    return parsed as AccessControl.IRole<TAction, TResource, TRole, TScope>
  }

  private _reportPolicyError(err: Error, rowId: string): void {
    if (this._onPolicyError) {
      this._onPolicyError(err, { adapter: 'redis', rowId })
      return
    }
    // eslint-disable-next-line no-console
    console.warn(`[duck-iam:redis] dropped malformed row "${rowId}": ${err.message}`)
  }

  // -- key helpers --

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

  // Separator below is a literal NUL byte (\0), not a space. Read tools render NUL as space.
  // NUL was chosen because it cannot appear in valid `TRole` / `TScope` strings; the runtime
  // guard catches any caller that smuggles one in past the type constraint.
  private _encodeAssignment(roleId: TRole, scope?: TScope | null): string {
    const r = roleId as string
    const s = (scope ?? '') as string
    if (r.includes('\0') || s.includes('\0')) {
      throw new Error('duck-iam: role / scope must not contain NUL bytes')
    }
    return `${r} ${s}`
  }
  private _decodeAssignment(member: string): { role: TRole; scope?: TScope } {
    const sep = member.indexOf(' ')
    if (sep === -1) return { role: member as TRole }
    const role = member.slice(0, sep) as TRole
    const scope = member.slice(sep + 1)
    return scope === '' ? { role } : { role, scope: scope as TScope }
  }

  /**
   * Lists every policy stored in the Redis hash.
   *
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns All policies decoded from the `policies` hash.
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async listPolicies(_opts?: Adapter.IReadOptions): Promise<AccessControl.IPolicy<TAction, TResource, TRole>[]> {
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
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async getPolicy(
    id: string,
    _opts?: Adapter.IReadOptions,
  ): Promise<AccessControl.IPolicy<TAction, TResource, TRole> | null> {
    const value = await this._client.hget(this._policiesKey(), id)
    return value ? this._safeParsePolicy(value, id) : null
  }

  /**
   * Stores or overwrites a policy under its ID.
   *
   * @param p - Provides the policy to persist.
   * @returns Resolves once the HSET completes.
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async savePolicy(p: AccessControl.IPolicy<TAction, TResource, TRole>): Promise<void> {
    await this._client.hset(this._policiesKey(), p.id, JSON.stringify(p))
  }

  /**
   * Removes a policy by ID.
   *
   * @param id - Identifies the policy to delete.
   * @returns Resolves once the HDEL completes.
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async deletePolicy(id: string): Promise<void> {
    await this._client.hdel(this._policiesKey(), id)
  }

  /**
   * Lists every role stored in the Redis hash.
   *
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns All roles decoded from the `roles` hash.
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async listRoles(_opts?: Adapter.IReadOptions): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope>[]> {
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
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async getRole(
    id: string,
    _opts?: Adapter.IReadOptions,
  ): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope> | null> {
    const value = await this._client.hget(this._rolesKey(), id)
    return value ? this._safeParseRole(value, id) : null
  }

  /**
   * Stores or overwrites a role under its ID.
   *
   * @param r - Provides the role to persist.
   * @returns Resolves once the HSET completes.
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async saveRole(r: AccessControl.IRole<TAction, TResource, TRole, TScope>): Promise<void> {
    await this._client.hset(this._rolesKey(), r.id, JSON.stringify(r))
  }

  /**
   * Removes a role by ID.
   *
   * @param id - Identifies the role to delete.
   * @returns Resolves once the HDEL completes.
   * @author wildduck2 <https://github.com/wildduck2>
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
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async getSubjectRoles(subjectId: string, _opts?: Adapter.IReadOptions): Promise<TRole[]> {
    const members = await this._client.smembers(this._assignmentsKey(subjectId))
    const roles = new Set<TRole>()
    for (const m of members) roles.add(this._decodeAssignment(m).role)
    return Array.from(roles)
  }

  /**
   * Lists scoped role assignments for a subject (excludes unscoped).
   *
   * @param subjectId - Identifies the subject whose scoped roles are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns Array of `(role, scope)` pairs.
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async getSubjectScopedRoles(
    subjectId: string,
    _opts?: Adapter.IReadOptions,
  ): Promise<Request.IScopedRole<TRole, TScope>[]> {
    const members = await this._client.smembers(this._assignmentsKey(subjectId))
    const out: Request.IScopedRole<TRole, TScope>[] = []
    for (const m of members) {
      const decoded = this._decodeAssignment(m)
      if (decoded.scope !== undefined) out.push({ role: decoded.role, scope: decoded.scope })
    }
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
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async assignRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void> {
    await this._client.sadd(this._assignmentsKey(subjectId), this._encodeAssignment(roleId, scope))
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
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async revokeRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void> {
    if (scope !== undefined) {
      await this._client.srem(this._assignmentsKey(subjectId), this._encodeAssignment(roleId, scope))
      return
    }
    const members = await this._client.smembers(this._assignmentsKey(subjectId))
    const targets = members.filter((m) => this._decodeAssignment(m).role === roleId)
    if (targets.length > 0) {
      await this._client.srem(this._assignmentsKey(subjectId), ...targets)
    }
  }

  /**
   * Fetches the attribute bag stored for a subject.
   *
   * @param subjectId - Identifies the subject whose attributes are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns The subject's attributes or `{}` when none are recorded.
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async getSubjectAttributes(subjectId: string, _opts?: Adapter.IReadOptions): Promise<Primitives.Attributes> {
    const value = await this._client.get(this._attrsKey(subjectId))
    if (!value) return {}
    try {
      const parsed = JSON.parse(value)
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        this._reportPolicyError(new Error(`Attributes for "${subjectId}" must be a JSON object`), subjectId)
        return {}
      }
      return parsed as Primitives.Attributes
    } catch (err) {
      this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), subjectId)
      return {}
    }
  }

  /**
   * Shallow-merges new attributes into the subject's existing bag.
   *
   * @param subjectId - Identifies the subject whose attributes are written.
   * @param attrs - Provides the partial attribute patch to merge in.
   * @returns Resolves once the SET completes.
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async setSubjectAttributes(subjectId: string, attrs: Primitives.Attributes): Promise<void> {
    const existing = await this.getSubjectAttributes(subjectId)
    const merged = { ...existing, ...attrs }
    await this._client.set(this._attrsKey(subjectId), JSON.stringify(merged))
  }
}
