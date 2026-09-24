import { hasIamErrorCode, throwIamError } from '../../core/errors'
import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../../core/types'
import { parsePolicyRow, parseRoleRow, validatePolicy, validateRole } from '../../core/validate'
import { iamAssertNoAssignOptions } from '../../shared/assign-options'
import { iamAssertRoleExists } from '../../shared/assignment-target'
import { iamAssertAttributesParam, iamNarrowAttributes } from '../../shared/attributes'
import {
  iamAssertSavablePolicy,
  iamAssertSavableRole,
  iamNormalizePolicy,
  iamRoleWithoutInherit,
  iamUnreadablePolicy,
  iamUnreadableRole,
} from '../../shared/rows'
import { iamAssertAssignableScope } from '../../shared/scope'
import { iamAsRoleLiteral, iamAsScopeLiteral } from '../../shared/tenant-literals'

/** Redis adapter integration types. Type-only namespace - zero bundle cost. */
export namespace IamRedis {
  /** Minimal Redis client surface {@link IamRedisAdapter} needs; ioredis and node-redis v4+ both satisfy it. */
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
    /** Optional Lua EVAL (ioredis positional shape), used to migrate legacy assignments atomically across processes. */
    eval?(script: string, numkeys: number, ...keysAndArgs: string[]): Promise<unknown>
    /**
     * Optional `KEYS`, used only by `deleteRole`; without it the role's grants stay and `onPolicyError` says so.
     * NOTE: `KEYS`, not `SCAN`, because ioredis and node-redis share its signature but not `SCAN`'s.
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
     * Called when a stored row fails JSON parse or shape validation, or a migration or cascade cannot complete.
     * NOTE: a bad role row is dropped; a bad policy row or attribute blob is reported and then thrown.
     */
    onPolicyError?: IamAdapter.RowErrorHandler<'redis'>
    /**
     * Rewrite legacy space-separated assignment members to the NUL-separated form on read. Off by default.
     * WARN: a spaced role id reads as role + scope; enable only if every member was written by the old encoder.
     */
    migrateLegacyAssignments?: boolean
  }
}

/**
 * Redis-backed adapter using hashes and sets.
 * INFO: keys are `${p}policies` (hash), `${p}roles` (hash), `${p}assignments:${id}` (set of `roleId\x00scope`)
 * and `${p}attrs:${id}` (JSON string), where `p` is `keyPrefix`.
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
   * Per-assignments-key promise chain, so a migration cannot re-add a member a concurrent revoke just removed.
   * NOTE: in-process only; across processes only the Lua `eval` migration is atomic.
   */
  private _assignmentWriteLocks = new Map<string, Promise<unknown>>()
  private _migrateLegacyAssignments: boolean

  constructor(config: IamRedis.IConfig<TClient>) {
    this._client = config.client
    this._prefix = config.keyPrefix ?? ''
    this._onPolicyError = config.onPolicyError
    this._migrateLegacyAssignments = config.migrateLegacyAssignments ?? false
  }

  /**
   * Parses and validates a stored policy; on failure it reports, then throws, as `_safeParseRole` does.
   * SECURITY: an unreadable policy is refused, not skipped, because it may be the one that denies.
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
      throw iamUnreadableRole('redis', rowId, err instanceof Error ? err.message : String(err))
    }
    const role = parseRoleRow<TAction, TResource, TRole, TScope>(parsed)
    if (role === null) {
      const issues = validateRole(parsed)
        .issues.map((i) => i.message)
        .join('; ')
      this._reportPolicyError(new Error(`Invalid role "${rowId}": ${issues}`), rowId)
      throw iamUnreadableRole('redis', rowId, issues)
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
   * Role/scope separator in an assignment member.
   * SECURITY: NUL is refused in role and scope at encode time, so a decode can never split in the wrong place.
   */
  private static readonly _SEP = '\0'

  /**
   * A member in the old space-separated form: exactly one space, no NUL. Always `false` unless opted in.
   * WARN: a global grant of a spaced role id looks identical; misreading it grants the prefix and deletes the original.
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
    // SECURITY: "" spells "no scope" in this encoding, so an empty scope would decode as a global grant.
    // Guarded here as well as in `assignRole`/`revokeRole`, so no internal caller has to remember.
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
      // Space-separated legacy member, decoded only under `migrateLegacyAssignments`; the read path re-encodes it.
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

  /** Runs `task` after any in-flight task on `key`, ordering writes to one assignments key within this process. */
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
   * Re-encodes the subject's legacy members in the NUL form. Idempotent and best-effort.
   * NOTE: failures are reported, not thrown, so a migration never blocks authorization; the next read retries.
   */
  private async _migrateLegacyAssignment(subjectId: string, members: string[]): Promise<void> {
    const legacy = members.filter((m) => this._isLegacyEncoded(m))
    if (legacy.length === 0) return
    const key = this._assignmentsKey(subjectId)
    // INFO: a Lua script runs atomically in Redis, so it is safe across processes; without `eval`, serialise locally.
    if (typeof this._client.eval === 'function') {
      await this._migrateLegacyAssignmentLua(key, subjectId, legacy)
      return
    }
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

  /** Lists every stored policy; throws if any row is unreadable. */
  async listPolicies(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IPolicy<TAction, TResource, TRole>[]> {
    const entries = await this._client.hgetall(this._policiesKey())
    const out: AccessControl.IPolicy<TAction, TResource, TRole>[] = []
    for (const [rowId, raw] of Object.entries(entries)) {
      const parsed = this._safeParsePolicy(raw, rowId)
      if (parsed) out.push(parsed)
    }
    return out
  }

  /** Fetches a policy by id, or `null` when absent; throws if the row is unreadable. */
  async getPolicy(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IPolicy<TAction, TResource, TRole> | null> {
    const value = await this._client.hget(this._policiesKey(), id)
    return value ? this._safeParsePolicy(value, id) : null
  }

  /** Stores or overwrites a policy under its id. */
  async savePolicy(p: AccessControl.IPolicy<TAction, TResource, TRole>): Promise<void> {
    iamAssertSavablePolicy('redis', p)
    await this._client.hset(this._policiesKey(), p.id, JSON.stringify(iamNormalizePolicy(p)))
  }

  /** Removes a policy by id. */
  async deletePolicy(id: string): Promise<void> {
    await this._client.hdel(this._policiesKey(), id)
  }

  /** Lists every stored role, dropping (and reporting) unreadable rows. */
  async listRoles(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope>[]> {
    const entries = await this._client.hgetall(this._rolesKey())
    const out: AccessControl.IRole<TAction, TResource, TRole, TScope>[] = []
    for (const [rowId, raw] of Object.entries(entries)) {
      const parsed = this._safeParseRole(raw, rowId)
      if (parsed) out.push(parsed)
    }
    return out
  }

  /** Fetches a role by id, or `null` when absent or unreadable. */
  async getRole(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope> | null> {
    const value = await this._client.hget(this._rolesKey(), id)
    return value ? this._safeParseRole(value, id) : null
  }

  /** Stores or overwrites a role under its id. */
  async saveRole(r: AccessControl.IRole<TAction, TResource, TRole, TScope>): Promise<void> {
    iamAssertSavableRole('redis', r)
    await this._client.hset(this._rolesKey(), r.id, JSON.stringify(r))
  }

  /**
   * Removes a role, every grant naming it (a `KEYS` sweep) and every `inherits` edge pointing at it.
   * SECURITY: a kept orphan grant or edge would be held again by its old subjects if the id is recreated.
   */
  async deleteRole(id: string): Promise<void> {
    await this._client.hdel(this._rolesKey(), id)
    await this._disinheritEverywhere(id)
    await this._revokeEverywhere(id)
  }

  /** Rewrites every readable role that inherits `deletedId` without that edge. */
  private async _disinheritEverywhere(deletedId: string): Promise<void> {
    const entries = await this._client.hgetall(this._rolesKey())
    for (const [rowId, raw] of Object.entries(entries)) {
      const role = this._safeParseRole(raw, rowId)
      if (role === null) continue
      const stripped = iamRoleWithoutInherit(role, deletedId)
      if (stripped !== null) await this._client.hset(this._rolesKey(), rowId, JSON.stringify(stripped))
    }
  }

  /**
   * Drops every assignment naming `roleId`, scoped and global, for every subject.
   * NOTE: each key is serialised because the read, filter and `SREM` are separate commands.
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

  /** Lists the subject's global role ids, deduplicated; scoped grants come from `getSubjectScopedRoles`. */
  async getSubjectRoles(subjectId: string, _opts?: IamAdapter.IReadOptions): Promise<TRole[]> {
    const members = await this._client.smembers(this._assignmentsKey(subjectId))
    const roles = new Set<TRole>()
    for (const m of members) {
      const decoded = this._decodeAssignment(m)
      if (decoded.scope !== undefined) continue
      roles.add(decoded.role)
    }
    await this._migrateLegacyAssignment(subjectId, members)
    return Array.from(roles)
  }

  /** Lists the subject's scoped `(role, scope)` grants; global grants are excluded. */
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
   * Grants a role, optionally within a scope. Idempotent (set semantics).
   * Refuses a role that is not stored; see {@link iamAssertRoleExists}.
   */
  async assignRole(subjectId: string, roleId: TRole, scope?: TScope, opts?: IamAdapter.IAssignOptions): Promise<void> {
    iamAssertAssignableScope('redis', scope)
    iamAssertNoAssignOptions('redis', opts)
    // Encode first, so an id this encoding cannot carry is refused for that reason, not as a missing role.
    const member = this._encodeAssignment(roleId, scope)
    // `hget`, not `hexists`, so the client interface does not need another method.
    iamAssertRoleExists('redis', (await this._client.hget(this._rolesKey(), roleId)) !== null)
    const key = this._assignmentsKey(subjectId)
    // Serialise against the migration path.
    await this._runSerialised(key, () => this._client.sadd(key, member))
  }

  /** Revokes a role grant; without `scope`, removes the role in every scope and globally. */
  async revokeRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void> {
    iamAssertAssignableScope('redis', scope, 'lookup')
    const key = this._assignmentsKey(subjectId)
    // Serialised so a racing migration cannot SADD the migrated member after this SREM.
    await this._runSerialised(key, async () => {
      if (scope !== undefined) {
        // Also removes the legacy space-separated member, so a partially migrated set is cleaned in one call.
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

  /** Reads the subject's attributes, or `{}` when none are stored; throws on a corrupt blob. */
  async getSubjectAttributes(subjectId: string, _opts?: IamAdapter.IReadOptions): Promise<IamPrimitives.Attributes> {
    const value = await this._client.get(this._attrsKey(subjectId))
    if (!value) return {}
    let parsed: unknown
    try {
      parsed = JSON.parse(value)
    } catch (err) {
      // SECURITY: corrupt is not empty; returning {} would strip the subject's attributes from every decision.
      this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), subjectId)
      throwIamError('IAM_ATTRIBUTES_CORRUPT', { adapter: 'redis', subjectId, reason: 'parse-failed' })
    }
    const attrs = iamNarrowAttributes(parsed)
    if (attrs === null) {
      this._reportPolicyError(
        new Error(`Attributes for "${subjectId}" must be a JSON object of scalar values`),
        subjectId,
      )
      throwIamError('IAM_ATTRIBUTES_CORRUPT', { adapter: 'redis', subjectId, reason: 'not-object' })
    }
    return attrs
  }

  /** Shallow-merges `attrs` into the subject's stored attributes. */
  async setSubjectAttributes(subjectId: string, attrs: IamPrimitives.Attributes): Promise<void> {
    iamAssertAttributesParam('redis', subjectId, attrs)
    // SECURITY: only a corrupt blob (`IAM_ATTRIBUTES_CORRUPT`) merges as `{}`, so an operator can overwrite it.
    // Any other read failure throws, since merging into a bag nobody read would replace it. Matched by code, not
    // `instanceof`, so a duplicated package copy of IamError still matches.
    let existing: IamPrimitives.Attributes
    try {
      existing = await this.getSubjectAttributes(subjectId)
    } catch (err) {
      if (!hasIamErrorCode(err, 'IAM_ATTRIBUTES_CORRUPT')) throw err
      this._reportPolicyError(err, subjectId)
      existing = {}
    }
    const merged = { ...existing, ...attrs }
    await this._client.set(this._attrsKey(subjectId), JSON.stringify(merged))
  }
}

/**
 * Escapes Redis `KEYS` glob metacharacters (`\` is the escape) so `keyPrefix` matches as literal text.
 * SECURITY: a raw `app[1]:` prefix would miss its own keys and sweep grants in the `app1:` namespace instead.
 */
function globLiteral(text: string): string {
  return text.replace(/[\\*?[\]]/g, (ch) => `\\${ch}`)
}

/** Factory around {@link IamRedisAdapter}, for callers who prefer functions to `new`. */
export function iamRedisAdapter(...args: ConstructorParameters<typeof IamRedisAdapter>): IamRedisAdapter {
  return new IamRedisAdapter(...args)
}
