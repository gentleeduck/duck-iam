// @ts-nocheck
import type { AccessControl, Adapter, Primitives, Request } from '../../core/types'
import { validatePolicy, validateRole } from '../../core/validate'

/**
 * Row shapes returned by Drizzle queries.
 */
interface PolicyRow {
  id: string
  name: string
  description: string | null
  version: number
  algorithm: string
  rules: string | unknown
  targets: string | unknown | null
}

/** Database row shape for the roles table. */
interface RoleRow {
  id: string
  name: string
  description: string | null
  permissions: string | unknown
  inherits: string | unknown | null
  scope: string | null
  metadata: string | unknown | null
}

/** Database row shape for the role-to-subject assignments table. */
interface AssignmentRow {
  subjectId: string
  roleId: string
  scope: string | null
}

/** Database row shape for the subject attributes table. */
interface AttrRow {
  subjectId: string
  data: string | unknown
}

/**
 * Drizzle adapter integration types. Type-only namespace - zero bundle cost.
 */
export namespace Drizzle {
  /**
   * Describes the wiring required to instantiate a {@link DrizzleAdapter}.
   */
  export interface IConfig {
    /** Provides the Drizzle database instance with select/insert/delete builders. */
    db: {
      select: () => { from: (table: unknown) => DrizzleQuery }
      insert: (table: unknown) => { values: (data: Record<string, unknown>) => DrizzleInsert }
      delete: (table: unknown) => { where: (condition: unknown) => Promise<unknown> }
    }
    /** Provides references to the four Drizzle table schemas used by the adapter. */
    tables: {
      policies: DrizzleTable
      roles: DrizzleTable
      assignments: DrizzleTable
      attrs: DrizzleTable
    }
    /** Provides Drizzle operator functions for building WHERE clauses. */
    ops: {
      eq: (col: unknown, val: unknown) => unknown
      and: (...conditions: unknown[]) => unknown
    }
    /**
     * Invoked when a stored row fails JSON parse or shape validation. The
     * malformed row is dropped from the result set; the rest are returned
     * intact. Wire this to your alerting pipeline so corrupt rows do not
     * silently vanish from authorization decisions.
     */
    onPolicyError?: (err: Error, ctx: { adapter: 'drizzle'; rowId: string }) => void
  }
}

/** Minimal shape of a Drizzle table object with optional column references. */
interface DrizzleTable {
  id?: unknown
  subjectId?: unknown
  roleId?: unknown
  scope?: unknown
  [key: string]: unknown
}

/** Minimal shape of a chainable Drizzle SELECT query. */
interface DrizzleQuery {
  where: (condition: unknown) => { limit: (n: number) => Promise<Record<string, unknown>[]> }
  limit: (n: number) => Promise<Record<string, unknown>[]>
  then: (onfulfilled: (value: Record<string, unknown>[]) => unknown) => Promise<unknown>
  [Symbol.iterator]?: unknown
}

/** Minimal shape of a chainable Drizzle INSERT query with conflict handling. */
interface DrizzleInsert {
  onConflictDoUpdate: (args: { target: unknown; set: Record<string, unknown> }) => Promise<unknown>
  onConflictDoNothing: () => Promise<unknown>
}

/**
 * Persists the access store via Drizzle ORM queries.
 *
 * Requires four tables (policies, roles, assignments, subject attributes). JSON
 * columns (rules, permissions, targets, metadata) are serialized on write and
 * parsed on read automatically.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @example
 * ```ts
 * import { drizzle } from 'drizzle-orm/node-postgres'
 * import { eq, and } from 'drizzle-orm'
 * const adapter = new DrizzleAdapter({ db: drizzle(pool), tables, ops: { eq, and } })
 * ```
 */
export class DrizzleAdapter<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
> implements Adapter.IAdapter<TAction, TResource, TRole, TScope>
{
  private _db: Drizzle.IConfig['db']
  private _t: Drizzle.IConfig['tables']
  private _eq: Drizzle.IConfig['ops']['eq']
  private _and: Drizzle.IConfig['ops']['and']
  private _onPolicyError?: (err: Error, ctx: { adapter: 'drizzle'; rowId: string }) => void

  /**
   * Creates a new Drizzle adapter.
   *
   * @param config - Provides the Drizzle db, tables, and operator functions.
   */
  constructor(config: Drizzle.IConfig) {
    this._db = config.db
    this._t = config.tables
    this._eq = config.ops.eq
    this._and = config.ops.and
    this._onPolicyError = config.onPolicyError
  }

  /**
   * Typed SELECT helpers consolidate the `as unknown as RowType[]` casts at
   * the module edge into one place. Drizzle's `select().from()` returns
   * untyped rows; row shapes are pinned at the boundary here.
   */
  private async _selectAll<T>(table: unknown): Promise<T[]> {
    return (await this._db.select().from(table)) as unknown as T[]
  }
  private async _selectFirst<T>(table: unknown, whereCol: unknown, whereVal: unknown): Promise<T | undefined> {
    const rows = (await this._db.select().from(table).where(this._eq(whereCol, whereVal)).limit(1)) as unknown as T[]
    return rows[0]
  }
  private async _selectWhere<T>(table: unknown, whereCol: unknown, whereVal: unknown): Promise<T[]> {
    return (await this._db.select().from(table).where(this._eq(whereCol, whereVal))) as unknown as T[]
  }

  private _reportPolicyError(err: Error, rowId: string): void {
    if (this._onPolicyError) {
      this._onPolicyError(err, { adapter: 'drizzle', rowId })
      return
    }
    // eslint-disable-next-line no-console
    console.warn(`[duck-iam:drizzle] dropped malformed row "${rowId}": ${err.message}`)
  }

  /**
   * Parse a row's JSON columns + validate the policy shape. Returns `null` on
   * any failure (parse error or invalid shape) so the caller can drop the row.
   */
  private _safeParsePolicy(row: PolicyRow): AccessControl.IPolicy<TAction, TResource, TRole> | null {
    let parsedRules: unknown
    let parsedTargets: unknown
    try {
      parsedRules =
        typeof row.rules === 'string' ? JSON.parse(row.rules) : (row.rules as AccessControl.IPolicy['rules'])
      parsedTargets = row.targets
        ? typeof row.targets === 'string'
          ? JSON.parse(row.targets)
          : (row.targets as AccessControl.IPolicy['targets'])
        : undefined
    } catch (err) {
      this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), row.id)
      return null
    }

    const candidate = {
      id: row.id,
      name: row.name,
      description: row.description ?? undefined,
      version: row.version,
      algorithm: row.algorithm as AccessControl.IPolicy['algorithm'],
      rules: parsedRules,
      targets: parsedTargets,
    }
    const result = validatePolicy(candidate)
    if (!result.valid) {
      this._reportPolicyError(
        new Error(`Invalid policy "${row.id}": ${result.issues.map((i) => i.message).join('; ')}`),
        row.id,
      )
      return null
    }
    return candidate as AccessControl.IPolicy<TAction, TResource, TRole>
  }

  private _safeParseRole(row: RoleRow): AccessControl.IRole<TAction, TResource, TRole, TScope> | null {
    let permissions: unknown
    let inherits: unknown
    let metadata: unknown
    try {
      permissions =
        typeof row.permissions === 'string'
          ? JSON.parse(row.permissions)
          : (row.permissions as AccessControl.IRole['permissions'])
      inherits = typeof row.inherits === 'string' ? JSON.parse(row.inherits) : ((row.inherits as string[] | null) ?? [])
      metadata = row.metadata
        ? typeof row.metadata === 'string'
          ? JSON.parse(row.metadata)
          : (row.metadata as AccessControl.IRole['metadata'])
        : undefined
    } catch (err) {
      this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), row.id)
      return null
    }

    const candidate = {
      id: row.id,
      name: row.name,
      description: row.description ?? undefined,
      permissions,
      inherits,
      scope: row.scope ?? undefined,
      metadata,
    }
    const result = validateRole(candidate)
    if (!result.valid) {
      this._reportPolicyError(
        new Error(`Invalid role "${row.id}": ${result.issues.map((i) => i.message).join('; ')}`),
        row.id,
      )
      return null
    }
    return candidate as AccessControl.IRole<TAction, TResource, TRole, TScope>
  }

  /**
   * Lists every policy in the database.
   *
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns All policies parsed from the policies table.
   */
  async listPolicies(_opts?: Adapter.IReadOptions): Promise<AccessControl.IPolicy<TAction, TResource, TRole>[]> {
    const rows = await this._selectAll<PolicyRow>(this._t.policies)
    const out: AccessControl.IPolicy<TAction, TResource, TRole>[] = []
    for (const row of rows) {
      const parsed = this._safeParsePolicy(row)
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
    _opts?: Adapter.IReadOptions,
  ): Promise<AccessControl.IPolicy<TAction, TResource, TRole> | null> {
    const row = await this._selectFirst<PolicyRow>(this._t.policies, this._t.policies.id, id)
    return row ? this._safeParsePolicy(row) : null
  }

  /**
   * Upserts a policy (inserts or updates on conflict).
   *
   * @param p - Provides the policy to persist.
   * @returns Resolves once the upsert completes.
   */
  async savePolicy(p: AccessControl.IPolicy<TAction, TResource, TRole>): Promise<void> {
    const data = serializePolicy(p)
    await this._db.insert(this._t.policies).values(data).onConflictDoUpdate({ target: this._t.policies.id, set: data })
  }

  /**
   * Removes a policy by ID.
   *
   * @param id - Identifies the policy to delete.
   * @returns Resolves once the delete completes.
   */
  async deletePolicy(id: string): Promise<void> {
    await this._db.delete(this._t.policies).where(this._eq(this._t.policies.id, id))
  }

  /**
   * Lists every role in the database.
   *
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns All roles parsed from the roles table.
   */
  async listRoles(_opts?: Adapter.IReadOptions): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope>[]> {
    const rows = await this._selectAll<RoleRow>(this._t.roles)
    const out: AccessControl.IRole<TAction, TResource, TRole, TScope>[] = []
    for (const row of rows) {
      const parsed = this._safeParseRole(row)
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
    _opts?: Adapter.IReadOptions,
  ): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope> | null> {
    const row = await this._selectFirst<RoleRow>(this._t.roles, this._t.roles.id, id)
    return row ? this._safeParseRole(row) : null
  }

  /**
   * Upserts a role (inserts or updates on conflict).
   *
   * @param r - Provides the role to persist.
   * @returns Resolves once the upsert completes.
   */
  async saveRole(r: AccessControl.IRole<TAction, TResource, TRole, TScope>): Promise<void> {
    const data = serializeRole(r)
    await this._db.insert(this._t.roles).values(data).onConflictDoUpdate({ target: this._t.roles.id, set: data })
  }

  /**
   * Removes a role by ID.
   *
   * @param id - Identifies the role to delete.
   * @returns Resolves once the delete completes.
   */
  async deleteRole(id: string): Promise<void> {
    await this._db.delete(this._t.roles).where(this._eq(this._t.roles.id, id))
  }

  /**
   * Lists deduplicated role IDs assigned to a subject.
   *
   * @param subjectId - Identifies the subject whose roles are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns Deduplicated array of role IDs.
   */
  async getSubjectRoles(subjectId: string, _opts?: Adapter.IReadOptions): Promise<TRole[]> {
    const rows = await this._selectWhere<AssignmentRow>(this._t.assignments, this._t.assignments.subjectId, subjectId)
    // Unscoped (global) roles only — mirrors file/memory/redis adapters.
    return [...new Set(rows.filter((r) => r.scope == null).map((r) => r.roleId as TRole))]
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
    _opts?: Adapter.IReadOptions,
  ): Promise<Request.IScopedRole<TRole, TScope>[]> {
    const rows = await this._selectWhere<AssignmentRow>(this._t.assignments, this._t.assignments.subjectId, subjectId)
    return rows.filter((r) => r.scope != null).map((r) => ({ role: r.roleId as TRole, scope: r.scope as TScope }))
  }

  /**
   * Grants a role to a subject, optionally restricted to a scope.
   *
   * No-ops on duplicate `(subject, role, scope)` rows.
   *
   * @param subjectId - Identifies the subject receiving the role.
   * @param roleId - Specifies the role being granted.
   * @param scope - Optional scope binding the assignment.
   * @returns Resolves once the insert completes.
   */
  async assignRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void> {
    await this._db
      .insert(this._t.assignments)
      .values({ subjectId, roleId, scope: scope ?? null })
      .onConflictDoNothing()
  }

  /**
   * Removes role assignments matching the given filters.
   *
   * @param subjectId - Identifies the subject losing the role.
   * @param roleId - Specifies the role being revoked.
   * @param scope - Optional scope filter to narrow the delete.
   * @returns Resolves once the delete completes.
   */
  async revokeRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void> {
    const conditions = [
      this._eq(this._t.assignments.subjectId, subjectId),
      this._eq(this._t.assignments.roleId, roleId),
    ]
    if (scope) conditions.push(this._eq(this._t.assignments.scope, scope))
    await this._db.delete(this._t.assignments).where(this._and(...conditions))
  }

  /**
   * Fetches the attribute bag stored for a subject.
   *
   * @param subjectId - Identifies the subject whose attributes are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns The subject's attributes or `{}` when none are recorded.
   */
  async getSubjectAttributes(subjectId: string, _opts?: Adapter.IReadOptions): Promise<Primitives.Attributes> {
    const row = await this._selectFirst<AttrRow>(this._t.attrs, this._t.attrs.subjectId, subjectId)
    if (!row) return {}
    const data = row.data
    if (typeof data !== 'string') return (data as Primitives.Attributes) ?? {}
    let parsed: unknown
    try {
      parsed = JSON.parse(data)
    } catch (err) {
      // Corruption is not "no attributes" — surface so the engine fails closed.
      this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), subjectId)
      throw new Error(`duck-iam DrizzleAdapter: corrupted attributes for "${subjectId}" (JSON parse failed)`)
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      this._reportPolicyError(new Error(`Attributes for "${subjectId}" must be a JSON object`), subjectId)
      throw new Error(`duck-iam DrizzleAdapter: corrupted attributes for "${subjectId}" (not a JSON object)`)
    }
    return parsed as Primitives.Attributes
  }

  /**
   * Shallow-merges new attributes into the subject's existing bag (upsert).
   *
   * @param subjectId - Identifies the subject whose attributes are written.
   * @param attrs - Provides the partial attribute patch to merge in.
   * @returns Resolves once the upsert completes.
   */
  async setSubjectAttributes(subjectId: string, attrs: Primitives.Attributes): Promise<void> {
    // Admin overwrite must recover from corrupt existing data instead of
    // locking the operator out.
    let existing: Primitives.Attributes
    try {
      existing = await this.getSubjectAttributes(subjectId)
    } catch (err) {
      this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), subjectId)
      existing = {}
    }
    const merged = JSON.stringify({ ...existing, ...attrs })
    await this._db
      .insert(this._t.attrs)
      .values({ subjectId, data: merged })
      .onConflictDoUpdate({ target: this._t.attrs.subjectId, set: { data: merged } })
  }
}

/** Converts a Policy object into a flat record with JSON-stringified columns for storage. */
function serializePolicy(p: AccessControl.IPolicy): Record<string, unknown> {
  return {
    id: p.id,
    name: p.name,
    description: p.description ?? null,
    version: p.version ?? 1,
    algorithm: p.algorithm,
    rules: JSON.stringify(p.rules),
    targets: p.targets ? JSON.stringify(p.targets) : null,
  }
}

/** Converts a Role object into a flat record with JSON-stringified columns for storage. */
function serializeRole(r: AccessControl.IRole): Record<string, unknown> {
  return {
    id: r.id,
    name: r.name,
    description: r.description ?? null,
    permissions: JSON.stringify(r.permissions),
    inherits: JSON.stringify(r.inherits ?? []),
    scope: r.scope ?? null,
    metadata: r.metadata ? JSON.stringify(r.metadata) : null,
  }
}
