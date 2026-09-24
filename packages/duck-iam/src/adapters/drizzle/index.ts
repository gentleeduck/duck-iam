import type { BinaryOperator, SQL, SQLWrapper } from 'drizzle-orm'
import type { MySqlTableWithColumns } from 'drizzle-orm/mysql-core/table'
import type { PgTableWithColumns } from 'drizzle-orm/pg-core/table'
import type { SQLiteTableWithColumns } from 'drizzle-orm/sqlite-core/table'
import { creditWrites } from '../../core/batch'
import type { IamConfig } from '../../core/config'
import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../../core/types'
import { parsePolicyRow, parseRoleRow, validatePolicy, validateRole } from '../../core/validate'
import { iamAssertValidAssignWindow } from '../../shared/assign-options'
import { iamIsForeignKeyViolation, iamUnknownRoleError } from '../../shared/assignment-target'
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
import type { Mysql } from './mysql/mysql.types'
import type { Pg } from './pg/pg.types'
import type { Sqlite } from './sqlite/sqlite.types'

/** IamDrizzle adapter integration types. Type-only namespace - zero bundle cost. */
export namespace IamDrizzle {
  type TTable<TType extends 'pg' | 'mysql' | 'sqlite'> = TType extends 'pg'
    ? PgTableWithColumns<any>
    : TType extends 'mysql'
      ? MySqlTableWithColumns<any>
      : SQLiteTableWithColumns<any>

  export interface IConfig<TDb extends AnyDrizzleDb, TType extends 'pg' | 'mysql' | 'sqlite'> {
    /**
     * SQL dialect of `db`; defaults to `'pg'`.
     * INFO: MySQL has no `ON CONFLICT` (it has `onDuplicateKeyUpdate()`/`ignore()`), so upserts branch on this.
     */
    dialect?: TType
    /** Drizzle database, or a transaction handle with the same builders. */
    db: TDb
    /** The four tables the adapter reads and writes. */
    tables: {
      [key in 'policies' | 'roles' | 'assignments' | 'attrs']: TTable<TType>
    }
    /** Drizzle operators for building WHERE clauses. */
    ops: {
      /**
       * drizzle-orm's own `eq`.
       * NOTE: typed as `BinaryOperator`; widening the params to `unknown` makes the real `eq` unassignable.
       */
      eq: BinaryOperator
      and: (...conditions: (SQLWrapper | undefined)[]) => SQL<unknown> | undefined
      /** drizzle-orm's `isNull`. Needed only for `updateAssignmentScope` to match an unscoped assignment. */
      isNull?: (col: SQLWrapper) => SQL
      /** drizzle-orm's `or`. Without it `revokeRoleMany` issues one `DELETE` per row instead of one statement. */
      or?: (...conditions: (SQLWrapper | undefined)[]) => SQL<unknown> | undefined
    }
    /**
     * JSON encoding: `'native'` (default) writes objects for Postgres `jsonb` / MySQL `json`; `'string'` stringifies
     * for SQLite or text columns. Reads accept both, so switching is migration-safe.
     */
    json?: 'native' | 'string'
    /**
     * Called when a stored row fails to parse or validate; wire it to alerting.
     * SECURITY: a bad role row is dropped, but a bad policy row throws so the engine denies.
     */
    onPolicyError?: IamAdapter.RowErrorHandler<'drizzle'>
  }

  /** Row shapes returned by IamDrizzle queries. */
  export type PolicyRow = Pg.PolicyRow | Mysql.PolicyRow | Sqlite.PolicyRow
  /** Database row shape for the roles table. */
  export type RoleRow = Pg.RoleRow | Mysql.RoleRow | Sqlite.RoleRow

  /** Database row shape for the role-to-subject assignments table. */
  export type AssignmentRow = Pg.AssignmentRow | Mysql.AssignmentRow | Sqlite.AssignmentRow

  /** Database row shape for the subject attributes table. */
  export type AttrRow = Pg.AttrRow | Mysql.AttrRow | Sqlite.AttrRow

  export type DrizzleTable = PgTableWithColumns<any> | MySqlTableWithColumns<any> | SQLiteTableWithColumns<any>

  /**
   * Structural db shape every supported Drizzle instance satisfies.
   * NOTE: not a union, which would make `db.select()` uncallable ("incompatible signatures").
   */
  export interface AnyDrizzleDb {
    select(...args: any[]): any
    insert(table: any): any
    update(table: any): any
    delete(table: any): any
  }
}

/**
 * Optional `ops` this process has already warned about.
 * NOTE: module-level because `withClient` re-creates the adapter per transaction; per-instance would warn on each one.
 */
const warnedMissingOps = new Set<'isNull' | 'or'>()
// NOTE: not exported; `entrypoint-naming.test.ts` limits this entrypoint's exports. Tests use `vi.resetModules()`.

/**
 * Provenance columns for an upsert: `createdBy` on insert, `updatedBy` on update.
 * Empty when no actor is named, so a table without the columns is untouched.
 */
function provenance(actor: string | undefined): {
  insert: Record<string, string>
  update: Record<string, string>
} {
  if (actor === undefined) return { insert: {}, update: {} }
  return { insert: { createdBy: actor }, update: { updatedBy: actor } }
}

/**
 * Warns once per process for each optional op left out; both fallbacks are correct but slower.
 * INFO: neither can be derived - `eq(col, null)` is not `IS NULL` in SQL, and `or` cannot be built from `eq`/`and`.
 */
function warnMissingOps(ops: { isNull?: unknown; or?: unknown }): void {
  const missing: string[] = []
  if (typeof ops.isNull !== 'function' && !warnedMissingOps.has('isNull')) {
    warnedMissingOps.add('isNull')
    missing.push(
      '`isNull` - updateAssignmentScope() cannot match an unscoped (NULL) assignment in place and falls back to revoke + assign',
    )
  }
  if (typeof ops.or !== 'function' && !warnedMissingOps.has('or')) {
    warnedMissingOps.add('or')
    missing.push('`or` - revokeRoleMany() issues one DELETE per row instead of one statement')
  }
  if (missing.length === 0) return
  try {
    console.warn(
      `[@gentleduck/iam:drizzle] running on a degraded path; ops is missing ${missing.join('; ')}. ` +
        'Pass them through from drizzle-orm: `ops: { eq, and, isNull, or }`.',
    )
  } catch {
    /* a closed stdout must not break adapter construction */
  }
}

/**
 * Epoch ms for an optional timestamp: `null` when absent, `NaN` when unparseable, `Infinity`/`-Infinity` kept as is.
 * INFO: Postgres `infinity` arrives as a JS number and `new Date(Infinity)` is invalid; as numbers the bounds compare.
 */
function epochMs(value: Date | string | number | null | undefined): number | null {
  if (value === null || value === undefined) return null
  if (typeof value === 'number' && !Number.isFinite(value)) return value
  return value instanceof Date ? value.getTime() : new Date(value).getTime()
}

/** One assignment row as read back from a `RETURNING` clause. `null` is the unscoped row, as the column stores it. */
type ReturnedTriple = { roleId: string; scope: string | null; subjectId: string }

/**
 * Reads the identifying columns out of untyped `RETURNING` rows.
 * A row without string ids is dropped, so an odd driver loses `changed` detail rather than corrupting the outcome list.
 */
function returnedTriples(returned: unknown): ReturnedTriple[] {
  const rows: unknown[] = Array.isArray(returned) ? returned : []
  const triples: ReturnedTriple[] = []
  for (const row of rows) {
    if (typeof row !== 'object' || row === null) continue
    if (!('subjectId' in row) || !('roleId' in row)) continue
    const { roleId, subjectId } = row
    if (typeof subjectId !== 'string' || typeof roleId !== 'string') continue
    triples.push({ roleId, scope: 'scope' in row && typeof row.scope === 'string' ? row.scope : null, subjectId })
  }
  return triples
}

/**
 * Drizzle-backed adapter for Postgres, MySQL and SQLite; needs 4 tables (policies, roles, assignments, subject attrs).
 * SECURITY: a malformed role row is reported and skipped; a malformed policy row is reported and throws.
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
 *
 * @example
 * ```ts
 * const adapter = new IamDrizzleAdapter({ db, tables, ops: { eq, and, isNull, or } })
 *
 * await db.transaction(async (tx) => {
 *   await adapter.withClient(tx).assignRole('user_1', 'admin')
 * })
 * ```
 */
export class IamDrizzleAdapter<
  TAction extends string,
  TResource extends string,
  TRole extends string,
  TScope extends string,
  TDb extends IamDrizzle.AnyDrizzleDb = IamDrizzle.AnyDrizzleDb,
  TType extends 'pg' | 'mysql' | 'sqlite' = 'pg',
> implements IamAdapter.IAdapter<TAction, TResource, TRole, TScope>
{
  private readonly _db: TDb
  private readonly _t: IamDrizzle.IConfig<TDb, TType>['tables']
  private readonly _eq: IamDrizzle.IConfig<TDb, TType>['ops']['eq']
  private readonly _and: IamDrizzle.IConfig<TDb, TType>['ops']['and']
  private readonly _isNull?: IamDrizzle.IConfig<TDb, TType>['ops']['isNull']
  private readonly _or?: IamDrizzle.IConfig<TDb, TType>['ops']['or']
  private readonly _json: 'native' | 'string'
  private readonly _dialect: 'pg' | 'mysql' | 'sqlite'
  private readonly _onPolicyError?: IamAdapter.RowErrorHandler<'drizzle'>
  /** Retained whole so {@link IamDrizzleAdapter.withClient} can re-make this adapter with only `db` swapped. */
  private readonly _config: IamDrizzle.IConfig<TDb, TType>

  /** Warns, once per process, when `ops.isNull` or `ops.or` is missing. */
  constructor(config: IamDrizzle.IConfig<TDb, TType>) {
    this._config = config
    this._db = config.db
    this._t = config.tables
    this._eq = config.ops.eq
    this._and = config.ops.and
    this._isNull = config.ops.isNull
    this._or = config.ops.or
    this._json = config.json ?? 'native'
    this._dialect = config.dialect ?? 'pg'
    this._onPolicyError = config.onPolicyError
    warnMissingOps(config.ops)
  }

  /**
   * Re-creates this adapter on `client` (e.g. a drizzle transaction), keeping the rest of the config.
   * NOTE: the cast is sound because a transaction handle has the same builders as its db.
   */
  withClient(client: unknown): IamDrizzleAdapter<TAction, TResource, TRole, TScope, TDb, TType> {
    return new IamDrizzleAdapter<TAction, TResource, TRole, TScope, TDb, TType>({
      ...this._config,
      db: client as TDb,
    })
  }

  /**
   * Insert-or-update keyed on `target` = `targetValue`.
   * NOTE: MySQL reads first instead of `onDuplicateKeyUpdate`, which fires on any unique index and could overwrite
   * another row.
   */
  private async _upsert(
    table: IamDrizzle.DrizzleTable,
    values: Record<string, unknown>,
    target: SQLWrapper,
    targetValue: unknown,
    set: Record<string, unknown>,
  ) {
    if (this._dialect !== 'mysql') {
      await this._db.insert(table).values(values).onConflictDoUpdate({ target, set })
      return
    }
    const existing = await this._db.select().from(table).where(this._eq(target, targetValue)).limit(1)
    if (existing.length > 0) {
      await this._db.update(table).set(set).where(this._eq(target, targetValue))
    } else {
      await this._db.insert(table).values(values)
    }
  }

  /**
   * Insert, skipping a row that already exists.
   * INFO: MySQL's insert-ignore is `.ignore()` before `.values()`, not a trailing call like `onConflictDoNothing()`.
   */
  private _insertOrSkip(table: IamDrizzle.DrizzleTable, values: Record<string, unknown> | Record<string, unknown>[]) {
    return this._dialect === 'mysql'
      ? this._db.insert(table).ignore().values(values)
      : this._db.insert(table).values(values).onConflictDoNothing()
  }

  /** Typed SELECT helpers: `db` is typed `any`, so `T` names the row shape without checking it. */
  private async _selectAll<T>(table: IamDrizzle.DrizzleTable): Promise<T[]> {
    return await this._db.select().from(table)
  }
  private async _selectFirst<T>(
    table: IamDrizzle.DrizzleTable,
    whereCol: SQLWrapper,
    whereVal: unknown,
  ): Promise<T | undefined> {
    const rows = await this._db.select().from(table).where(this._eq(whereCol, whereVal)).limit(1)
    return rows[0]
  }
  private async _selectWhere<T>(table: IamDrizzle.DrizzleTable, whereCol: SQLWrapper, whereVal: unknown): Promise<T[]> {
    return await this._db.select().from(table).where(this._eq(whereCol, whereVal))
  }

  private _reportPolicyError(err: Error, rowId: string): void {
    if (this._onPolicyError) {
      this._onPolicyError(err, { adapter: 'drizzle', rowId })
      return
    }
    console.warn(`[@gentleduck/iam:drizzle] malformed row "${rowId}": ${err.message}`)
  }

  /**
   * Parses a policy row's JSON columns and validates its shape.
   * SECURITY: throws instead of returning `null`, since a dropped policy may be the deny.
   * See {@link iamUnreadablePolicy}.
   */
  private _safeParsePolicy(row: IamDrizzle.PolicyRow): AccessControl.IPolicy<TAction, TResource, TRole> | null {
    let parsedRules: unknown
    let parsedTargets: unknown
    try {
      // No cast: a native column holds whatever was written, and `parsePolicyRow` below decides it is a policy.
      parsedRules = typeof row.rules === 'string' ? JSON.parse(row.rules) : row.rules
      parsedTargets = row.targets
        ? typeof row.targets === 'string'
          ? JSON.parse(row.targets)
          : row.targets
        : undefined
    } catch (err) {
      const detail = err instanceof Error ? err : new Error(String(err))
      this._reportPolicyError(detail, row.id)
      throw iamUnreadablePolicy('drizzle', row.id, detail.message)
    }

    const candidate = {
      id: row.id,
      name: row.name,
      ...(row.description === null || row.description === undefined ? {} : { description: row.description }),
      version: row.version,
      algorithm: row.algorithm,
      rules: parsedRules,
      ...(parsedTargets === undefined ? {} : { targets: parsedTargets }),
    }
    const policy = parsePolicyRow<TAction, TResource, TRole>(candidate)
    if (policy === null) {
      const issues = validatePolicy(candidate)
        .issues.map((i) => i.message)
        .join('; ')
      this._reportPolicyError(new Error(`Invalid policy "${row.id}": ${issues}`), row.id)
      throw iamUnreadablePolicy('drizzle', row.id, issues)
    }
    return policy
  }

  private _safeParseRole(row: IamDrizzle.RoleRow): AccessControl.IRole<TAction, TResource, TRole, TScope> | null {
    let permissions: unknown
    let inherits: unknown
    let metadata: unknown
    try {
      permissions = typeof row.permissions === 'string' ? JSON.parse(row.permissions) : row.permissions
      inherits = typeof row.inherits === 'string' ? JSON.parse(row.inherits) : (row.inherits ?? [])
      metadata = row.metadata ? (typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata) : undefined
    } catch (err) {
      this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), row.id)
      throw iamUnreadableRole('drizzle', row.id, err instanceof Error ? err.message : String(err))
    }

    // Omit absent columns instead of writing `undefined`, so every adapter reads a role back with the same keys.
    const candidate = {
      id: row.id,
      name: row.name,
      ...(row.description === null || row.description === undefined ? {} : { description: row.description }),
      permissions,
      // An empty `inherits` is how an absent one is stored. Any other value, even a non-array, goes to `parseRoleRow`.
      ...(Array.isArray(inherits) && inherits.length === 0 ? {} : { inherits }),
      ...(row.scope === null || row.scope === undefined ? {} : { scope: row.scope }),
      ...(metadata === undefined ? {} : { metadata }),
    }
    const role = parseRoleRow<TAction, TResource, TRole, TScope>(candidate)
    if (role === null) {
      const issues = validateRole(candidate)
        .issues.map((i) => i.message)
        .join('; ')
      this._reportPolicyError(new Error(`Invalid role "${row.id}": ${issues}`), row.id)
      throw iamUnreadableRole('drizzle', row.id, issues)
    }
    return role
  }

  /**
   * Epoch ms of the next future `startsAt`/`expiresAt` on the subject's grants (or `null`), so caches expire on time.
   * Computed in JS because the dialects spell `MIN(CASE ...)` differently.
   * See {@link IamAdapter.ISubjectStore.getSubjectGrantBoundary}.
   */
  async getSubjectGrantBoundary(subjectId: string): Promise<number | null> {
    const rows = await this._selectWhere<IamDrizzle.AssignmentRow>(
      this._t.assignments,
      this._t.assignments.subjectId,
      subjectId,
    )
    const now = Date.now()
    let next: number | null = null
    for (const row of rows) {
      for (const bound of [epochMs(row.startsAt), epochMs(row.expiresAt)]) {
        if (bound === null || !Number.isFinite(bound) || bound <= now) continue
        if (next === null || bound < next) next = bound
      }
    }
    return next
  }

  /**
   * True when `now` is inside `[startsAt, expiresAt)`; a missing bound is open.
   * SECURITY: an unreadable bound makes the row inactive, since `NaN` fails both comparisons and would read as live.
   */
  private _isActive(row: IamDrizzle.AssignmentRow, now: number): boolean {
    const startsAt = epochMs(row.startsAt)
    const expiresAt = epochMs(row.expiresAt)
    // NOTE: `Number.isNaN`, not `!Number.isFinite`: Postgres spells an open-ended bound as `Infinity`,
    // which must stay active.
    if (startsAt !== null && Number.isNaN(startsAt)) return false
    if (expiresAt !== null && Number.isNaN(expiresAt)) return false
    if (startsAt !== null && now < startsAt) return false
    if (expiresAt !== null && now >= expiresAt) return false
    return true
  }

  /**
   * Parses an assignment's `attributes` column.
   * A corrupt value is reported and dropped, not thrown, so one bad field does not fail the whole role list.
   */
  private _parseAssignmentAttributes(row: IamDrizzle.AssignmentRow): IamPrimitives.Attributes | undefined {
    const raw = row.attributes
    if (raw === null || raw === undefined) return undefined
    // Name the row by subject when it has no `id`.
    const rowId = row.id ?? row.subjectId
    let value: unknown
    try {
      value = typeof raw === 'string' ? JSON.parse(raw) : raw
    } catch (err) {
      this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), rowId)
      return undefined
    }
    const attrs = iamNarrowAttributes(value)
    if (attrs === null) {
      this._reportPolicyError(
        new Error(`Assignment attributes for "${rowId}" must be a JSON object of scalar values`),
        rowId,
      )
      return undefined
    }
    return attrs
  }

  /** Lists every policy; throws if any policy row is unreadable. */
  async listPolicies(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IPolicy<TAction, TResource, TRole>[]> {
    const rows = await this._selectAll<IamDrizzle.PolicyRow>(this._t.policies)
    const out: AccessControl.IPolicy<TAction, TResource, TRole>[] = []
    for (const row of rows) {
      const parsed = this._safeParsePolicy(row)
      if (parsed) out.push(parsed)
    }
    return out
  }

  /** Fetches a policy by ID, or `null` when absent. */
  async getPolicy(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IPolicy<TAction, TResource, TRole> | null> {
    const row = await this._selectFirst<IamDrizzle.PolicyRow>(this._t.policies, this._t.policies.id, id)
    return row ? this._safeParsePolicy(row) : null
  }

  /** Upserts a policy; `opts.actor` fills `created_by` on insert and `updated_by` on update. */
  async savePolicy(
    p: AccessControl.IPolicy<TAction, TResource, TRole>,
    opts?: IamAdapter.IActorOptions,
  ): Promise<void> {
    iamAssertSavablePolicy('drizzle', p)
    const data = serializePolicy(iamNormalizePolicy(p), this._json)
    const who = provenance(opts?.actor)
    await this._upsert(this._t.policies, { ...data, ...who.insert }, this._t.policies.id, p.id, {
      ...data,
      ...who.update,
    })
  }

  /** Removes a policy by ID. */
  async deletePolicy(id: string): Promise<void> {
    await this._db.delete(this._t.policies).where(this._eq(this._t.policies.id, id))
  }

  /** Lists every readable role; unreadable rows are reported and skipped. */
  async listRoles(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope>[]> {
    const rows = await this._selectAll<IamDrizzle.RoleRow>(this._t.roles)
    const out: AccessControl.IRole<TAction, TResource, TRole, TScope>[] = []
    for (const row of rows) {
      const parsed = this._safeParseRole(row)
      if (parsed) out.push(parsed)
    }
    return out
  }

  /** Fetches a role by ID, or `null` when absent or unreadable. */
  async getRole(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope> | null> {
    const row = await this._selectFirst<IamDrizzle.RoleRow>(this._t.roles, this._t.roles.id, id)
    return row ? this._safeParseRole(row) : null
  }

  /** Upserts a role; `opts.actor` fills `created_by` on insert and `updated_by` on update. */
  async saveRole(
    r: AccessControl.IRole<TAction, TResource, TRole, TScope>,
    opts?: IamAdapter.IActorOptions,
  ): Promise<void> {
    iamAssertSavableRole('drizzle', r)
    const data = serializeRole(r, this._json)
    const who = provenance(opts?.actor)
    await this._upsert(this._t.roles, { ...data, ...who.insert }, this._t.roles.id, r.id, { ...data, ...who.update })
  }

  /**
   * Removes a role by ID; the grants go with it through `ON DELETE CASCADE`, the `inherits` edges here.
   * SECURITY: an orphan edge re-attaches to a role recreated under the same id, as an orphan grant would.
   */
  async deleteRole(id: string): Promise<void> {
    await this._db.delete(this._t.roles).where(this._eq(this._t.roles.id, id))
    for (const row of await this._selectAll<IamDrizzle.RoleRow>(this._t.roles)) {
      const role = this._safeParseRole(row)
      if (role === null) continue
      const stripped = iamRoleWithoutInherit(role, id)
      if (stripped === null) continue
      await this._db
        .update(this._t.roles)
        .set({ inherits: encodeJson(stripped.inherits ?? [], this._json) })
        .where(this._eq(this._t.roles.id, stripped.id))
    }
  }

  /** Deduplicated IDs of the subject's active *unscoped* roles; scoped ones come from `getSubjectScopedRoles`. */
  async getSubjectRoles(subjectId: string, _opts?: IamAdapter.IReadOptions): Promise<TRole[]> {
    const rows = await this._selectWhere<IamDrizzle.AssignmentRow>(
      this._t.assignments,
      this._t.assignments.subjectId,
      subjectId,
    )
    const now = Date.now()
    return [
      ...new Set(
        rows.filter((r) => r.scope == null && this._isActive(r, now)).map((r) => iamAsRoleLiteral<TRole>(r.roleId)),
      ),
    ]
  }

  /** The subject's active scoped assignments as `(role, scope, attributes?)`; unscoped rows are excluded. */
  async getSubjectScopedRoles(
    subjectId: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<IamRequest.IScopedRole<TRole, TScope>[]> {
    const rows = await this._selectWhere<IamDrizzle.AssignmentRow>(
      this._t.assignments,
      this._t.assignments.subjectId,
      subjectId,
    )
    const now = Date.now()
    // Narrow per row: a `filter` predicate does not narrow `r.scope`, and a `null` must never pass as a scope.
    const out: IamRequest.IScopedRole<TRole, TScope>[] = []
    for (const r of rows) {
      if (r.scope === null || r.scope === undefined || !this._isActive(r, now)) continue
      const attributes = this._parseAssignmentAttributes(r)
      out.push({
        role: iamAsRoleLiteral<TRole>(r.roleId),
        scope: iamAsScopeLiteral<TScope>(r.scope),
        ...(attributes !== undefined && { attributes }),
      })
    }
    return out
  }

  /** Grants a role, optionally scoped, time-bounded and attributed; a duplicate `(subject, role, scope)` is a no-op. */
  async assignRole(subjectId: string, roleId: TRole, scope?: TScope, opts?: IamAdapter.IAssignOptions): Promise<void> {
    iamAssertAssignableScope('drizzle', scope)
    iamAssertValidAssignWindow('drizzle', opts)
    await this._refusingUnknownRole(() =>
      this._insertOrSkip(this._t.assignments, {
        subjectId,
        roleId,
        scope: scope ?? null,
        startsAt: opts?.startsAt ?? null,
        expiresAt: opts?.expiresAt ?? null,
        attributes: opts?.attributes ? encodeJson(opts.attributes, this._json) : null,
        // Spread rather than written as null, so a table without the column is untouched unless an actor is named.
        ...(opts?.actor !== undefined && { createdBy: opts.actor }),
      }),
    )
  }

  /**
   * Runs a write and turns a `fk_iam_assignments_role` violation into the shared unknown-role error, keeping `cause`.
   * NOTE: the FK is the check, since a pre-read races a role delete; drizzle hides the constraint under `Failed query`.
   */
  private async _refusingUnknownRole<T>(write: () => Promise<T>): Promise<T> {
    try {
      return await write()
    } catch (err) {
      if (!iamIsForeignKeyViolation(err)) throw err
      throw iamUnknownRoleError('drizzle', err)
    }
  }

  /** Removes the subject's assignment of `roleId`; with no `scope`, removes it in every scope. */
  async revokeRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void> {
    iamAssertAssignableScope('drizzle', scope, 'lookup')
    const conditions = [
      this._eq(this._t.assignments.subjectId, subjectId),
      this._eq(this._t.assignments.roleId, roleId),
    ]
    if (scope !== undefined) conditions.push(this._eq(this._t.assignments.scope, scope))
    await this._db.delete(this._t.assignments).where(this._and(...conditions))
  }

  /**
   * Grants every row in one multi-row insert, skipping existing grants like {@link IamDrizzleAdapter.assignRole}.
   * @returns Indices of rows this call inserted (read via `RETURNING`), or `null` on MySQL.
   */
  async assignRoleMany(rows: readonly IamAdapter.IAssignRow<TRole, TScope>[]): Promise<readonly number[] | null> {
    for (const r of rows) {
      iamAssertAssignableScope('drizzle', r.scope)
      iamAssertValidAssignWindow('drizzle', r.opts)
    }
    if (rows.length === 0) return []
    // A multi-row insert takes its column list from the value objects, so if any row names an actor, every row
    // carries `createdBy` (null where it has none).
    const anyActor = rows.some((r) => r.opts?.actor !== undefined)
    const statement = this._insertOrSkip(
      this._t.assignments,
      rows.map((r) => ({
        subjectId: r.subjectId,
        roleId: r.roleId,
        scope: r.scope ?? null,
        startsAt: r.opts?.startsAt ?? null,
        expiresAt: r.opts?.expiresAt ?? null,
        attributes: r.opts?.attributes ? encodeJson(r.opts.attributes, this._json) : null,
        ...(anyActor && { createdBy: r.opts?.actor ?? null }),
      })),
    )
    // INFO: MySQL's insert-ignore has no `RETURNING`; `null` tells the engine to leave `changed` unset.
    if (this._dialect === 'mysql') {
      await this._refusingUnknownRole(() => Promise.resolve(statement))
      return null
    }
    // `r.scope ?? null` matches the stored column, keeping an unscoped row distinct from the `''` scope.
    return creditWrites(
      rows,
      returnedTriples(await this._refusingUnknownRole(() => statement.returning())),
      (r, t) => r.subjectId === t.subjectId && r.roleId === t.roleId && (r.scope ?? null) === t.scope,
    )
  }

  /**
   * Revokes every row with one `DELETE ... WHERE a OR b`, or one delete per row without `ops.or`.
   * A row with no `scope` revokes the role in every scope.
   * @returns Indices of rows that removed a grant (read via `RETURNING`), or `null` on MySQL.
   */
  async revokeRoleMany(rows: readonly IamAdapter.ITripleRow<TRole, TScope>[]): Promise<readonly number[] | null> {
    for (const r of rows) iamAssertAssignableScope('drizzle', r.scope, 'lookup')
    if (rows.length === 0) return []
    const rowCondition = (r: IamAdapter.ITripleRow<TRole, TScope>): SQLWrapper | undefined => {
      const conditions: (SQLWrapper | undefined)[] = [
        this._eq(this._t.assignments.subjectId, r.subjectId),
        this._eq(this._t.assignments.roleId, r.roleId),
      ]
      if (r.scope !== undefined) conditions.push(this._eq(this._t.assignments.scope, r.scope))
      return this._and(...conditions)
    }
    const or = this._or
    const wheres = or ? [or(...rows.map(rowCondition))] : rows.map(rowCondition)

    // INFO: MySQL has no `RETURNING` on `DELETE`.
    if (this._dialect === 'mysql') {
      for (const where of wheres) await this._db.delete(this._t.assignments).where(where)
      return null
    }

    const gone: ReturnedTriple[] = []
    for (const where of wheres) {
      gone.push(...returnedTriples(await this._db.delete(this._t.assignments).where(where).returning()))
    }
    // An unscoped request is credited with any removed scope; a scoped one only with its own (`''` is not `null`).
    return creditWrites(
      rows,
      gone,
      (r, t) => r.subjectId === t.subjectId && r.roleId === t.roleId && (r.scope === undefined || r.scope === t.scope),
    )
  }

  /**
   * Moves `(subjectId, roleId, fromScope)` to `toScope` in place; if `toScope` is already held, drops the source row.
   * Returns `false` without `ops.isNull` (unscoped needs `IS NULL`) or when nothing matches, so the engine
   * falls back to revoke + assign.
   */
  async updateAssignmentScope(
    subjectId: string,
    roleId: TRole,
    fromScope: TScope | undefined,
    toScope: TScope | undefined,
    actor?: string,
  ): Promise<boolean> {
    iamAssertAssignableScope('drizzle', fromScope, 'lookup')
    iamAssertAssignableScope('drizzle', toScope)
    if (!this._isNull) return false
    const table = this._t.assignments
    const isNull = this._isNull
    const scopeCondition = (scope: TScope | undefined): SQLWrapper =>
      scope === undefined ? isNull(table.scope) : this._eq(table.scope, scope)

    const fromCondition = this._and(
      this._eq(table.subjectId, subjectId),
      this._eq(table.roleId, roleId),
      scopeCondition(fromScope),
    )
    const existing = await this._db.select().from(this._t.assignments).where(fromCondition).limit(1)
    if (!existing[0]) return false

    const toCondition = this._and(
      this._eq(table.subjectId, subjectId),
      this._eq(table.roleId, roleId),
      scopeCondition(toScope),
    )
    const conflict = await this._db.select().from(this._t.assignments).where(toCondition).limit(1)
    if (conflict[0]) {
      // Target scope is already granted; drop the source row rather than collide with it.
      await this._db.delete(this._t.assignments).where(fromCondition)
      return true
    }

    await this._db
      .update(this._t.assignments)
      .set({ scope: toScope ?? null, ...(actor !== undefined && { updatedBy: actor }) })
      .where(fromCondition)
    return true
  }

  /**
   * The subject's attribute bag, or `{}` when none is stored.
   * SECURITY: a corrupt bag throws, so the engine fails closed.
   */
  async getSubjectAttributes(subjectId: string, _opts?: IamAdapter.IReadOptions): Promise<IamPrimitives.Attributes> {
    const stored = await this._readStoredAttributes(subjectId)
    if (!stored.ok) throw stored.error
    return stored.attrs
  }

  /** Reads and narrows the stored bag: a failed query rejects, a corrupt row resolves `{ ok: false }`. */
  private async _readStoredAttributes(
    subjectId: string,
  ): Promise<
    { readonly ok: true; readonly attrs: IamPrimitives.Attributes } | { readonly ok: false; readonly error: Error }
  > {
    const row = await this._selectFirst<IamDrizzle.AttrRow>(this._t.attrs, this._t.attrs.subjectId, subjectId)
    if (!row) return { ok: true, attrs: {} }
    const data = row.data
    if (typeof data === 'string') {
      let parsed: unknown
      try {
        parsed = JSON.parse(data)
      } catch (err) {
        // SECURITY: corruption is not "no attributes"; surface it so the engine fails closed.
        this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), subjectId)
        return {
          ok: false,
          error: new Error(`[@gentleduck/iam:drizzle] corrupted attributes for "${subjectId}" (JSON parse failed)`),
        }
      }
      return this._narrowStoredAttributes(parsed, subjectId)
    }
    // SECURITY: no `null -> {}` shortcut. `data` is NOT NULL, so `null` here is a stored `'null'::jsonb`, and `{}`
    // would disable every deny rule that tests an attribute. `_narrowStoredAttributes` refuses it.
    return this._narrowStoredAttributes(data ?? null, subjectId)
  }

  private _narrowStoredAttributes(
    value: unknown,
    subjectId: string,
  ): { readonly ok: true; readonly attrs: IamPrimitives.Attributes } | { readonly ok: false; readonly error: Error } {
    const attrs = iamNarrowAttributes(value)
    if (attrs === null) {
      const got = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value
      this._reportPolicyError(
        new Error(`Attributes for "${subjectId}" must be a JSON object of scalar values (got ${got})`),
        subjectId,
      )
      return {
        ok: false,
        error: new Error(`[@gentleduck/iam:drizzle] corrupted attributes for "${subjectId}" (not a JSON object)`),
      }
    }
    return { ok: true, attrs }
  }

  /** Shallow-merges `attrs` into the subject's stored bag (upsert); a corrupt stored bag is reported and replaced. */
  async setSubjectAttributes(
    subjectId: string,
    attrs: IamPrimitives.Attributes,
    opts?: IamAdapter.IActorOptions,
  ): Promise<void> {
    // Refuse a non-object `attrs`, which would spread into per-character keys.
    iamAssertAttributesParam('drizzle', subjectId, attrs)
    // Only a corrupt bag is overwritten; a failed read propagates instead of replacing the bag.
    const stored = await this._readStoredAttributes(subjectId)
    if (!stored.ok) this._reportPolicyError(stored.error, subjectId)
    const existing = stored.ok ? stored.attrs : {}
    const mergedObj = { ...existing, ...attrs }
    const merged = this._json === 'string' ? JSON.stringify(mergedObj) : mergedObj
    const who = provenance(opts?.actor)
    await this._upsert(this._t.attrs, { subjectId, data: merged, ...who.insert }, this._t.attrs.subjectId, subjectId, {
      data: merged,
      ...who.update,
    })
  }
}

/** Encodes JSON for storage: stringified in `'string'` mode, untouched in `'native'` mode (`jsonb`/`json`). */
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

/**
 * Creates an {@link IamDrizzleAdapter} typed from an engine config.
 *
 * @template TEngine - The access control engine configuration.
 * @template TDb - The Drizzle db instance.
 * @template TType - The Drizzle db dialect.
 * @template Params - The action, resource, role, scope and env types inferred from `TEngine`.
 */
export function createIamDrizzleAdapter<
  TEngine extends IamConfig.IAccessConfig<any, any, any, any, any>,
  TDb extends IamDrizzle.AnyDrizzleDb,
  TType extends 'pg' | 'mysql' | 'sqlite' = 'pg',
  Params extends string[] = TEngine extends IamConfig.IAccessConfig<
    infer TAction,
    infer TResource,
    infer TRole,
    infer TScope,
    infer TEnv
  >
    ? [TAction, TResource, TRole, TScope, TEnv]
    : never,
>(config: IamDrizzle.IConfig<TDb, TType>): IamDrizzleAdapter<Params[0], Params[1], Params[2], Params[3], TDb, TType> {
  return new IamDrizzleAdapter(config)
}

/** Factory around {@link IamDrizzleAdapter}, for callers who prefer functions to `new`. */
export function iamDrizzleAdapter<
  TAction extends string,
  TResource extends string,
  TRole extends string,
  TScope extends string,
  TDb extends IamDrizzle.AnyDrizzleDb = IamDrizzle.AnyDrizzleDb,
  TType extends 'pg' | 'mysql' | 'sqlite' = 'pg',
>(
  ...args: ConstructorParameters<typeof IamDrizzleAdapter<TAction, TResource, TRole, TScope, TDb, TType>>
): IamDrizzleAdapter<TAction, TResource, TRole, TScope, TDb, TType> {
  return new IamDrizzleAdapter<TAction, TResource, TRole, TScope, TDb, TType>(...args)
}
