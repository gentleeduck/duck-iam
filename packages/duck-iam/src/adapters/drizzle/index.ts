import type { SQL, SQLWrapper } from 'drizzle-orm'
import type { MySqlDatabase } from 'drizzle-orm/mysql-core'
import type { MySqlTableWithColumns } from 'drizzle-orm/mysql-core/table'
import type { PgDatabase } from 'drizzle-orm/pg-core'
import type { PgTableWithColumns } from 'drizzle-orm/pg-core/table'
import type { BaseSQLiteDatabase } from 'drizzle-orm/sqlite-core'
import type { SQLiteTableWithColumns } from 'drizzle-orm/sqlite-core/table'
import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../../core/types'
import { parsePolicyRow, parseRoleRow, validatePolicy, validateRole } from '../../core/validate'
import type {
  iamAssignments as AssignmentMysql,
  iamSubjectAttrs as AttrMysql,
  iamPolicies as PolicyMysql,
  iamRoles as RoleMysql,
} from './schema/mysql'
import type {
  iamAssignments as AssignmentPg,
  iamSubjectAttrs as AttrPg,
  iamPolicies as PolicyPg,
  iamRoles as RolePg,
} from './schema/pg'
import type {
  iamAssignments as AssignmentSqlite,
  iamSubjectAttrs as AttrSqlite,
  iamPolicies as PolicySqlite,
  iamRoles as RoleSqlite,
} from './schema/sqlite'

/** IamDrizzle adapter integration types. Type-only namespace - zero bundle cost. */
export namespace IamDrizzle {
  /**
   * Describes the wiring required to instantiate a {@link IamDrizzleAdapter}.
   *
   * @example
   * ```ts
   * import { drizzle } from 'drizzle-orm/node-postgres'
   * import { eq, and } from 'drizzle-orm'
   * import { iamPolicies, iamRoles, iamAssignments, iamSubjectAttrs } from './schema'
   *
   * const config: IamDrizzle.IConfig = {
   *   db: drizzle(pool),
   *   tables: { policies: iamPolicies, roles: iamRoles, assignments: iamAssignments, attrs: iamSubjectAttrs },
   *   ops: { eq, and },
   * }
   * ```
   */
  /**
   * Shape that the four IAM tables must satisfy.
   * Pass your concrete table types (from `iamPolicies`, `iamRoles`, etc.)
   * as `TTables` so TypeScript infers column types throughout the adapter.
   */
  export type ITableSchema<TDb extends AnyDrizzleDb = AnyDrizzleDb> = {
    policies: DbTableFor<TDb>
    roles: DbTableFor<TDb>
    assignments: DbTableFor<TDb>
    attrs: DbTableFor<TDb>
  }

  export interface IConfig<
    TDb extends AnyDrizzleDb = AnyDrizzleDb,
    TTables extends ITableSchema<TDb> = ITableSchema<TDb>,
  > {
    /** Provides the IamDrizzle database instance with select/insert/delete builders. */
    db: TDb
    /** Provides references to the four IamDrizzle table schemas used by the adapter. */
    tables: TTables
    /** Provides IamDrizzle operator functions for building WHERE clauses. */
    ops: {
      eq: (col: unknown, val: unknown) => unknown
      and: (...conditions: (SQLWrapper | undefined)[]) => SQL<unknown> | undefined
    }
    /**
     * JSON column encoding strategy.
     *
     * - `'native'` (default) writes plain objects/arrays so Postgres `jsonb`
     *   and MySQL `json` columns store queryable JSON (enables GIN indexes,
     *   `jsonb_typeof` checks, and avoids double-encoding).
     * - `'string'` `JSON.stringify`s every payload - required for SQLite, whose
     *   columns are TEXT, or any deployment storing JSON in a text column.
     *
     * The read path accepts both shapes, so switching is migration-safe.
     */
    json?: 'native' | 'string'
    /**
     * Invoked when a stored row fails JSON parse or shape validation. The
     * malformed row is dropped from the result set; the rest are returned
     * intact. Wire this to your alerting pipeline so corrupt rows do not
     * silently vanish from authorization decisions.
     */
    onPolicyError?: (err: Error, ctx: { adapter: 'drizzle'; rowId: string }) => void
  }

  /** Row shapes returned by IamDrizzle queries. */
  export type PolicyRow =
    | typeof PolicyPg.$inferSelect
    | typeof PolicyMysql.$inferSelect
    | typeof PolicySqlite.$inferSelect
  /** Database row shape for the roles table. */
  export type RoleRow = typeof RolePg.$inferSelect | typeof RoleMysql.$inferSelect | typeof RoleSqlite.$inferSelect

  /** Database row shape for the role-to-subject assignments table. */
  export type AssignmentRow =
    | typeof AssignmentPg.$inferSelect
    | typeof AssignmentMysql.$inferSelect
    | typeof AssignmentSqlite.$inferSelect

  /** Database row shape for the subject attributes table. */
  export type AttrRow = typeof AttrPg.$inferSelect | typeof AttrMysql.$inferSelect | typeof AttrSqlite.$inferSelect

  export type DrizzleTable = PgTableWithColumns<any> | MySqlTableWithColumns<any> | SQLiteTableWithColumns<any>

  /**
   * Structural db interface — all supported Drizzle instances satisfy this.
   * Using a structural interface (not a union) lets TypeScript call
   * `db.select()` on a generic `TDb extends AnyDrizzleDb` without the
   * "each member of the union has incompatible signatures" error.
   */
  export interface AnyDrizzleDb {
    select(...args: any[]): any
    insert(table: any): any
    delete(table: any): any
  }

  /**
   * Maps a concrete db instance to its matching table type so that
   * passing a pg db with sqlite tables is a compile error.
   * Falls back to `any` when `TDb` is the bare structural default —
   * this keeps `IamDrizzle.IConfig` (no type args) permissive for tests/mocks.
   */
  export type DbTableFor<TDb extends AnyDrizzleDb> =
    TDb extends PgDatabase<any, any, any>
      ? PgTableWithColumns<any>
      : TDb extends MySqlDatabase<any, any, any, any>
        ? MySqlTableWithColumns<any>
        : TDb extends BaseSQLiteDatabase<any, any, any, any>
          ? SQLiteTableWithColumns<any>
          : any
}

/**
 * IamDrizzle-backed adapter; needs 4 tables (policies, roles, assignments, subject attributes) and `{ eq, and }` ops.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 *
 * @example
 * ```ts
 * import { drizzle } from 'drizzle-orm/node-postgres'
 * import { eq, and } from 'drizzle-orm'
 * import { IamDrizzleAdapter } from '@gentleduck/iam/adapters/drizzle'
 *
 * const adapter = new IamDrizzleAdapter({ db: drizzle(pool), tables, ops: { eq, and } })
 * const engine = new IamEngine({ adapter })
 * ```
 */
export class IamDrizzleAdapter<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
  TDb extends IamDrizzle.AnyDrizzleDb = IamDrizzle.AnyDrizzleDb,
  TTables extends IamDrizzle.ITableSchema<TDb> = IamDrizzle.ITableSchema<TDb>,
> implements IamAdapter.IAdapter<TAction, TResource, TRole, TScope>
{
  private _db: TDb
  private _t: TTables
  private _eq: IamDrizzle.IConfig['ops']['eq']
  private _and: IamDrizzle.IConfig['ops']['and']
  private _json: 'native' | 'string'
  private _onPolicyError?: (err: Error, ctx: { adapter: 'drizzle'; rowId: string }) => void

  /**
   * Creates a new IamDrizzle adapter.
   *
   * @param config - Provides the IamDrizzle db, tables, and operator functions.
   */
  constructor(config: IamDrizzle.IConfig<TDb, TTables>) {
    this._db = config.db
    this._t = config.tables
    this._eq = config.ops.eq
    this._and = config.ops.and
    this._json = config.json ?? 'native'
    this._onPolicyError = config.onPolicyError
  }

  /**
   * Typed SELECT helpers consolidate the `as unknown as RowType[]` casts at
   * the module edge into one place. IamDrizzle's `select().from()` returns
   * untyped rows; row shapes are pinned at the boundary here.
   */
  private async _selectAll<T>(table: IamDrizzle.DrizzleTable): Promise<T[]> {
    return await this._db.select().from(table)
  }
  private async _selectFirst<T>(
    table: IamDrizzle.DrizzleTable,
    whereCol: unknown,
    whereVal: unknown,
  ): Promise<T | undefined> {
    const rows = await this._db.select().from(table).where(this._eq(whereCol, whereVal)).limit(1)
    return rows[0]
  }
  private async _selectWhere<T>(table: IamDrizzle.DrizzleTable, whereCol: unknown, whereVal: unknown): Promise<T[]> {
    return await this._db.select().from(table).where(this._eq(whereCol, whereVal))
  }

  private _reportPolicyError(err: Error, rowId: string): void {
    if (this._onPolicyError) {
      this._onPolicyError(err, { adapter: 'drizzle', rowId })
      return
    }
    // eslint-disable-next-line no-console
    console.warn(`[@gentleduck/iam:drizzle] dropped malformed row "${rowId}": ${err.message}`)
  }

  /**
   * Parse a row's JSON columns + validate the policy shape. Returns `null` on
   * any failure (parse error or invalid shape) so the caller can drop the row.
   */
  private _safeParsePolicy(row: IamDrizzle.PolicyRow): AccessControl.IPolicy<TAction, TResource, TRole> | null {
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
    const policy = parsePolicyRow<TAction, TResource, TRole>(candidate)
    if (policy === null) {
      const issues = validatePolicy(candidate)
        .issues.map((i) => i.message)
        .join('; ')
      this._reportPolicyError(new Error(`Invalid policy "${row.id}": ${issues}`), row.id)
      return null
    }
    return policy
  }

  private _safeParseRole(row: IamDrizzle.RoleRow): AccessControl.IRole<TAction, TResource, TRole, TScope> | null {
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
    const role = parseRoleRow<TAction, TResource, TRole, TScope>(candidate)
    if (role === null) {
      const issues = validateRole(candidate)
        .issues.map((i) => i.message)
        .join('; ')
      this._reportPolicyError(new Error(`Invalid role "${row.id}": ${issues}`), row.id)
      return null
    }
    return role
  }

  /**
   * Lists every policy in the database.
   *
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns All policies parsed from the policies table.
   */
  async listPolicies(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IPolicy<TAction, TResource, TRole>[]> {
    const rows = await this._selectAll<IamDrizzle.PolicyRow>(this._t.policies)
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
    _opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IPolicy<TAction, TResource, TRole> | null> {
    const row = await this._selectFirst<IamDrizzle.PolicyRow>(this._t.policies, this._t.policies.id, id)
    return row ? this._safeParsePolicy(row) : null
  }

  /**
   * Upserts a policy (inserts or updates on conflict).
   *
   * @param p - Provides the policy to persist.
   * @returns Resolves once the upsert completes.
   */
  async savePolicy(p: AccessControl.IPolicy<TAction, TResource, TRole>): Promise<void> {
    const data = serializePolicy(p, this._json)
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
  async listRoles(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope>[]> {
    const rows = await this._selectAll<IamDrizzle.RoleRow>(this._t.roles)
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
    _opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope> | null> {
    const row = await this._selectFirst<IamDrizzle.RoleRow>(this._t.roles, this._t.roles.id, id)
    return row ? this._safeParseRole(row) : null
  }

  /**
   * Upserts a role (inserts or updates on conflict).
   *
   * @param r - Provides the role to persist.
   * @returns Resolves once the upsert completes.
   */
  async saveRole(r: AccessControl.IRole<TAction, TResource, TRole, TScope>): Promise<void> {
    const data = serializeRole(r, this._json)
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
  async getSubjectRoles(subjectId: string, _opts?: IamAdapter.IReadOptions): Promise<TRole[]> {
    const rows = await this._selectWhere<IamDrizzle.AssignmentRow>(
      this._t.assignments,
      this._t.assignments.subjectId,
      subjectId,
    )
    // Unscoped (global) roles only - mirrors file/memory/redis adapters.
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
    _opts?: IamAdapter.IReadOptions,
  ): Promise<IamRequest.IScopedRole<TRole, TScope>[]> {
    const rows = await this._selectWhere<IamDrizzle.AssignmentRow>(
      this._t.assignments,
      this._t.assignments.subjectId,
      subjectId,
    )
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
    await this._db.delete(this._t.assignments).where(this._and(...(conditions as (SQLWrapper | undefined)[])))
  }

  /**
   * Fetches the attribute bag stored for a subject.
   *
   * @param subjectId - Identifies the subject whose attributes are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns The subject's attributes or `{}` when none are recorded.
   */
  async getSubjectAttributes(subjectId: string, _opts?: IamAdapter.IReadOptions): Promise<IamPrimitives.Attributes> {
    const row = await this._selectFirst<IamDrizzle.AttrRow>(this._t.attrs, this._t.attrs.subjectId, subjectId)
    if (!row) return {}
    const data = row.data
    if (typeof data === 'string') {
      let parsed: unknown
      try {
        parsed = JSON.parse(data)
      } catch (err) {
        // Corruption is not "no attributes" - surface so the engine fails closed.
        this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), subjectId)
        throw new Error(`[@gentleduck/iam:drizzle] corrupted attributes for "${subjectId}" (JSON parse failed)`)
      }
      return this._validateAttributesShape(parsed, subjectId)
    }
    if (data === null || data === undefined) return {}
    return this._validateAttributesShape(data, subjectId)
  }

  private _validateAttributesShape(value: unknown, subjectId: string): IamPrimitives.Attributes {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      const got = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value
      this._reportPolicyError(new Error(`Attributes for "${subjectId}" must be a JSON object (got ${got})`), subjectId)
      throw new Error(`[@gentleduck/iam:drizzle] corrupted attributes for "${subjectId}" (not a JSON object)`)
    }
    return value as IamPrimitives.Attributes
  }

  /**
   * Shallow-merges new attributes into the subject's existing bag (upsert).
   *
   * @param subjectId - Identifies the subject whose attributes are written.
   * @param attrs - Provides the partial attribute patch to merge in.
   * @returns Resolves once the upsert completes.
   */
  async setSubjectAttributes(subjectId: string, attrs: IamPrimitives.Attributes): Promise<void> {
    // Admin overwrite must recover from corrupt existing data instead of
    // locking the operator out.
    let existing: IamPrimitives.Attributes
    try {
      existing = await this.getSubjectAttributes(subjectId)
    } catch (err) {
      this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), subjectId)
      existing = {}
    }
    const mergedObj = { ...existing, ...attrs }
    const merged = this._json === 'string' ? JSON.stringify(mergedObj) : mergedObj
    await this._db
      .insert(this._t.attrs)
      .values({ subjectId, data: merged })
      .onConflictDoUpdate({ target: this._t.attrs.subjectId, set: { data: merged } })
  }
}

/**
 * Encodes a JSON payload for storage: `JSON.stringify` in `'string'` mode
 * (SQLite / text columns), or the value untouched in `'native'` mode so
 * IamDrizzle hands a real object to a `jsonb`/`json` column.
 */
function encodeJson(value: unknown, mode: 'native' | 'string'): unknown {
  return mode === 'string' ? JSON.stringify(value) : value
}

/** Converts a Policy object into a flat record for storage under the given JSON mode. */
function serializePolicy(p: AccessControl.IPolicy, json: 'native' | 'string'): Record<string, unknown> {
  return {
    id: p.id,
    name: p.name,
    description: p.description ?? null,
    version: p.version ?? 1,
    algorithm: p.algorithm,
    rules: encodeJson(p.rules, json),
    targets: p.targets ? encodeJson(p.targets, json) : null,
  }
}

/** Converts a Role object into a flat record for storage under the given JSON mode. */
function serializeRole(r: AccessControl.IRole, json: 'native' | 'string'): Record<string, unknown> {
  return {
    id: r.id,
    name: r.name,
    description: r.description ?? null,
    permissions: encodeJson(r.permissions, json),
    inherits: encodeJson(r.inherits ?? [], json),
    scope: r.scope ?? null,
    metadata: r.metadata ? encodeJson(r.metadata, json) : null,
  }
}
