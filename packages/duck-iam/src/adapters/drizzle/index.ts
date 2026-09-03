import type { SQL, SQLWrapper } from 'drizzle-orm'
import type { MySqlTableWithColumns } from 'drizzle-orm/mysql-core/table'
import type { PgTableWithColumns } from 'drizzle-orm/pg-core/table'
import type { SQLiteTableWithColumns } from 'drizzle-orm/sqlite-core/table'
import { creditWrites } from '../../core/batch'
import type { IamConfig } from '../../core/config'
import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../../core/types'
import { parsePolicyRow, parseRoleRow, validatePolicy, validateRole } from '../../core/validate'
import { iamIsForeignKeyViolation, iamUnknownRoleError } from '../../shared/assignment-target'
import { iamAssertAttributesParam, iamNarrowAttributes } from '../../shared/attributes'
import {
  iamAssertSavablePolicy,
  iamAssertSavableRole,
  iamNormalizePolicy,
  iamUnreadablePolicy,
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
     * Which SQL dialect `db` speaks. MySQL has no `ON CONFLICT` clause - its
     * insert builder exposes `onDuplicateKeyUpdate()`/`ignore()` instead of
     * `onConflictDoUpdate()`/`onConflictDoNothing()`, so upserts branch on
     * this at runtime. Defaults to `'pg'`, which shares its conflict API
     * with `'sqlite'`.
     */
    dialect?: TType
    /** Provides the IamDrizzle database instance with select/insert/delete builders. */
    db: TDb
    /** Provides references to the four IamDrizzle table schemas used by the adapter. */
    tables: {
      [key in 'policies' | 'roles' | 'assignments' | 'attrs']: TTable<TType>
    }
    /** Provides IamDrizzle operator functions for building WHERE clauses. */
    ops: {
      eq: (col: unknown, val: unknown) => unknown
      and: (...conditions: (SQLWrapper | undefined)[]) => SQL<unknown> | undefined
      /** Builds an `IS NULL` condition. Optional - required only for `updateAssignmentScope` to match a global (unscoped) assignment. */
      isNull?: (col: unknown) => SQLWrapper
      /**
       * Builds an `OR` of conditions. Optional - required only to collapse
       * `revokeRoleMany` into a single `DELETE`; without it that method revokes
       * one row at a time, which is correct but not one statement.
       */
      or?: (...conditions: (SQLWrapper | undefined)[]) => SQL<unknown> | undefined
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
   * Structural db interface: all supported Drizzle instances satisfy this.
   * Using a structural interface (not a union) lets TypeScript call
   * `db.select()` on a generic `TDb extends AnyDrizzleDb` without the
   * "each member of the union has incompatible signatures" error.
   */
  export interface AnyDrizzleDb {
    select(...args: any[]): any
    insert(table: any): any
    update(table: any): any
    delete(table: any): any
  }
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
/**
 * Which optional `ops` this process has already complained about.
 *
 * Module-level rather than per-instance because {@link IamDrizzleAdapter.withClient}
 * re-constructs the adapter for every transaction: a per-instance flag would
 * turn one misconfiguration into one warning per transaction, which is how a
 * startup diagnostic becomes log noise operators filter out.
 */
const warnedMissingOps = new Set<'isNull' | 'or'>()
// Not exported as a reset seam: this entrypoint ships exactly the adapter class
// and its factory, and `entrypoint-naming.test.ts` enforces that. Tests that
// need a fresh warning state re-import the module (`vi.resetModules()`).

/**
 * Warn once per process for each optional operator the caller left out.
 *
 * Both omissions are *correct* but slow, and silently so: without `or`,
 * `revokeRoleMany` degrades from one `DELETE` to one per row; without `isNull`,
 * `updateAssignmentScope` cannot express the `IS NULL` an unscoped assignment
 * needs and falls back to revoke + assign - two writes, and briefly no grant at
 * all. Neither can be derived: `eq(col, null)` is not `IS NULL` in SQL, and
 * there is no way to synthesise an `OR` builder from `eq` and `and`. So the
 * only honest fix is to say so at construction, where the caller can act on it.
 */
/**
 * Provenance columns for an upsert: `created_by` on the row this call inserts,
 * `updated_by` on the row it overwrites.
 *
 * Split deliberately. `created_by` answers "who first put this here" and must
 * not move on a later edit; `updated_by` answers "who touched it last" and must.
 * Both are spread rather than written as null, so a table predating the columns
 * is untouched unless the caller actually names an actor.
 */
function provenance(actor: string | undefined): {
  insert: Record<string, string>
  update: Record<string, string>
} {
  if (actor === undefined) return { insert: {}, update: {} }
  return { insert: { createdBy: actor }, update: { updatedBy: actor } }
}

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
 * Epoch ms for an optional timestamp column: `null` when absent, `NaN` when
 * unparseable, and `Infinity` / `-Infinity` passed through as themselves.
 *
 * Postgres spells "never expires" as `infinity`, and node-postgres parses it to
 * the JS number, not a Date. `new Date(Infinity)` is an Invalid Date, so that
 * spelling used to collapse into the same `NaN` an unreadable column produces,
 * and a grant marked as never expiring read as inactive - a wrong deny, on the
 * value an operator writes precisely to mean "always". Kept as numbers, the two
 * bounds compare the way they read: `now < -Infinity` is false, so a
 * `-infinity` start is always begun, and `now >= Infinity` is false, so an
 * `infinity` expiry never lapses. The other two spellings (`starts_at =
 * infinity`, `expires_at = -infinity`) fall out inactive from the same
 * comparisons, which is also what they mean.
 */
function epochMs(value: Date | string | number | null | undefined): number | null {
  if (value === null || value === undefined) return null
  if (typeof value === 'number' && !Number.isFinite(value)) return value
  return value instanceof Date ? value.getTime() : new Date(value).getTime()
}

/** One assignment row as read back from a `RETURNING` clause. `null` is the unscoped row, as the column stores it. */
type ReturnedTriple = { roleId: string; scope: string | null; subjectId: string }

/**
 * Read the identifying columns out of untyped `RETURNING` rows.
 *
 * `AnyDrizzleDb` types every builder as `any`, so these rows arrive with no
 * shape at all. Reading them defensively rather than asserting a type means a
 * driver that answers with something unexpected loses the `changed` detail
 * instead of corrupting the outcome list: a row that cannot supply string ids
 * is dropped, and an unscoped row's `null` becomes the empty scope.
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
  /** Retained whole so {@link withClient} can re-make this adapter with only `db` swapped. */
  private readonly _config: IamDrizzle.IConfig<TDb, TType>

  /**
   * Creates a new IamDrizzle adapter.
   *
   * @param config - Provides the IamDrizzle db, tables, and operator functions.
   */
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
   * Re-makes this adapter against `client`, keeping every other config field.
   *
   * A drizzle transaction handle exposes the same `select`/`insert`/`update`/
   * `delete` builders as the db it came from, which is why the cast is sound -
   * and why it lives here, in the layer that owns the driver type, instead of
   * leaking drizzle into the engine.
   */
  withClient(client: unknown): IamDrizzleAdapter<TAction, TResource, TRole, TScope, TDb, TType> {
    return new IamDrizzleAdapter<TAction, TResource, TRole, TScope, TDb, TType>({
      ...this._config,
      db: client as TDb,
    })
  }

  /**
   * Insert-or-update keyed on `target`'s unique/PK column, currently
   * `targetValue`. MySQL has no `ON CONFLICT` clause, and its
   * `onDuplicateKeyUpdate` fires on *any* unique-index violation, not only
   * `target`'s - `iamPolicies` also has a unique `name`, `iamRoles` a unique
   * `(name, scope)`. Saving a policy/role with a fresh id but a name (or
   * name+scope) that already belongs to a *different* row would silently
   * overwrite that unrelated row's data - including its id - instead of
   * erroring, where pg/sqlite's `target`-scoped `onConflictDoUpdate` throws
   * because the conflict isn't on the column it was told to expect.
   *
   * So on MySQL this checks for the row by `target` first and issues a
   * plain update or insert accordingly, rather than a blanket
   * `onDuplicateKeyUpdate`: a genuine secondary-unique-index collision then
   * surfaces as a thrown duplicate-entry error from the insert, matching
   * pg/sqlite's fail-closed behaviour instead of corrupting the other row.
   */
  private async _upsert(
    table: IamDrizzle.DrizzleTable,
    values: Record<string, unknown>,
    target: unknown,
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
   * Insert, silently skipping a row that already exists. MySQL's
   * insert-ignore is a builder-order modifier (`.ignore()` before
   * `.values()`), not a trailing call like `onConflictDoNothing()`.
   */
  private _insertOrSkip(table: IamDrizzle.DrizzleTable, values: Record<string, unknown> | Record<string, unknown>[]) {
    return this._dialect === 'mysql'
      ? this._db.insert(table).ignore().values(values)
      : this._db.insert(table).values(values).onConflictDoNothing()
  }

  /**
   * Typed SELECT helpers. Drizzle's `select().from()` returns rows whose shape
   * it cannot know for a table passed as a value, so the row type is named once
   * here per call site rather than at each of them.
   *
   * These no longer contain any `as unknown as RowType[]`; the earlier version
   * of this comment described that removed behaviour, which is exactly the
   * comment a reader trusts when deciding not to look.
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
    console.warn(`[@gentleduck/iam:drizzle] malformed row "${rowId}": ${err.message}`)
  }

  /**
   * Parse a row's JSON columns + validate the policy shape.
   *
   * Throws on any failure - a bad JSON column or an invalid shape - rather than
   * returning `null` for the caller to skip. See {@link iamUnreadablePolicy}:
   * a dropped policy may be the one that denies. `_safeParseRole` below still
   * returns `null`, because role permissions are allow-only.
   */
  private _safeParsePolicy(row: IamDrizzle.PolicyRow): AccessControl.IPolicy<TAction, TResource, TRole> | null {
    let parsedRules: unknown
    let parsedTargets: unknown
    try {
      // No cast on the non-string branch. The column is `jsonb`, so its value
      // is whatever was written to the row - `parsePolicyRow` below is what
      // decides it is a policy, and asserting the type first only made the
      // laundering look like a check.
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
      return null
    }

    // Absent columns are omitted, not set to `undefined`, the way
    // `_safeParsePolicy` above already does it. A key holding `undefined` is
    // still a key: `Object.keys` lists it, `JSON.stringify` drops it, and
    // `toEqual` ignores it, so "does this role have a description" got three
    // different answers depending which one the consumer asked - and a role
    // saved as `{id,name,permissions}` read back from Postgres with seven keys
    // and from memory with three.
    const candidate = {
      id: row.id,
      name: row.name,
      ...(row.description === null || row.description === undefined ? {} : { description: row.description }),
      permissions,
      // An empty `inherits` is what the column's `[]` default produces for a
      // role saved without one, which is the same thing as not having it.
      // Anything else - including a value that is not an array - is passed
      // through for `parseRoleRow` to refuse.
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
      return null
    }
    return role
  }

  /**
   * True unless `now` falls outside `[startsAt, expiresAt)`. Both bounds are
   * optional. A bound that is present but unreadable makes the assignment
   * inactive: `NaN` fails both comparisons, so an expired row with a corrupt
   * `expiresAt` would otherwise read as a live grant.
   */
  private _isActive(row: IamDrizzle.AssignmentRow, now: number): boolean {
    const startsAt = epochMs(row.startsAt)
    const expiresAt = epochMs(row.expiresAt)
    // `Number.isNaN`, not `!Number.isFinite`: only an *unreadable* bound makes
    // the row inactive on sight. `±Infinity` is readable - it is how Postgres
    // spells an open-ended bound - and the comparisons below give it the right
    // answer on their own.
    if (startsAt !== null && Number.isNaN(startsAt)) return false
    if (expiresAt !== null && Number.isNaN(expiresAt)) return false
    if (startsAt !== null && now < startsAt) return false
    if (expiresAt !== null && now >= expiresAt) return false
    return true
  }

  /**
   * Parses an assignment's `attributes` column. Corruption drops just this field
   * (reported, not thrown) - unlike subject attributes, a bad value here shouldn't
   * fail the whole role list.
   */
  private _parseAssignmentAttributes(row: IamDrizzle.AssignmentRow): IamPrimitives.Attributes | undefined {
    const raw = row.attributes
    if (raw === null || raw === undefined) return undefined
    // mysql's id has no adapter-side default, so AssignmentRow.id is nullable there.
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
    const now = Date.now()
    return [
      ...new Set(
        rows.filter((r) => r.scope == null && this._isActive(r, now)).map((r) => iamAsRoleLiteral<TRole>(r.roleId)),
      ),
    ]
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
    const now = Date.now()
    // `filter` with a plain predicate does not narrow the mapped element, so
    // `r.scope` is still `string | null` here. The old `r.scope as TScope`
    // erased that: change the predicate and a `null` scope would travel on as a
    // scope value, matching a scoped check it should never match. Narrowing per
    // row keeps the two in step.
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

  /**
   * Grants a role to a subject, optionally restricted to a scope.
   *
   * No-ops on duplicate `(subject, role, scope)` rows.
   *
   * @param subjectId - Identifies the subject receiving the role.
   * @param roleId - Specifies the role being granted.
   * @param scope - Optional scope binding the assignment.
   * @param opts - Optional temporal bounds and per-grant attributes.
   * @returns Resolves once the insert completes.
   */
  async assignRole(subjectId: string, roleId: TRole, scope?: TScope, opts?: IamAdapter.IAssignOptions): Promise<void> {
    iamAssertAssignableScope('drizzle', scope)
    await this._refusingUnknownRole(() =>
      this._insertOrSkip(this._t.assignments, {
        subjectId,
        roleId,
        scope: scope ?? null,
        startsAt: opts?.startsAt ?? null,
        expiresAt: opts?.expiresAt ?? null,
        attributes: opts?.attributes ? encodeJson(opts.attributes, this._json) : null,
        // Spread rather than written as null, so a table without the column is
        // untouched unless the caller actually names an actor. The pg and mysql
        // schemas here declare `created_by`; this is what finally fills it.
        ...(opts?.actor !== undefined && { createdBy: opts.actor }),
      }),
    )
  }

  /**
   * Runs a write that may violate `fk_iam_assignments_role` and reports the
   * violation the way the other five adapters do.
   *
   * The database is the check here - checking first would leave a window where
   * the role is deleted before the insert lands - but drizzle buries the
   * constraint on `.cause` under a `Failed query: <sql>` message, so without
   * this an operator sees the statement and never the reason. The original
   * error is kept as `cause`.
   *
   * @param write - The insert to run.
   * @returns Whatever the write returns.
   */
  private async _refusingUnknownRole<T>(write: () => Promise<T>): Promise<T> {
    try {
      return await write()
    } catch (err) {
      if (!iamIsForeignKeyViolation(err)) throw err
      throw iamUnknownRoleError('drizzle', err)
    }
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
    iamAssertAssignableScope('drizzle', scope)
    const conditions = [
      this._eq(this._t.assignments.subjectId, subjectId),
      this._eq(this._t.assignments.roleId, roleId),
    ]
    if (scope !== undefined) conditions.push(this._eq(this._t.assignments.scope, scope))
    await this._db.delete(this._t.assignments).where(this._and(...(conditions as (SQLWrapper | undefined)[])))
  }

  /**
   * Grants every triple with one multi-row insert, reusing the same
   * insert-or-skip conflict handling as {@link assignRole}.
   *
   * Reports which rows this statement actually created. `RETURNING` on the
   * insert names them for free - the conflict clause has already skipped the
   * duplicates, so the driver hands back exactly the new grants on the round
   * trip the write was making anyway. A duplicate is still `ok` to the caller;
   * it is reported as `changed: false`, matching {@link assignRole}, which
   * treats an existing grant as success.
   *
   * @param rows - The triples to grant, each with its optional temporal bounds.
   * @returns Indices of the rows this call granted, or `null` on MySQL - see below.
   */
  async assignRoleMany(rows: readonly IamAdapter.IAssignRow<TRole, TScope>[]): Promise<readonly number[] | null> {
    for (const r of rows) iamAssertAssignableScope('drizzle', r.scope)
    if (rows.length === 0) return []
    // All-or-nothing across the batch: a multi-row insert builds its column
    // list from the value objects, so including `createdBy` on some rows and
    // not others would produce rows the driver has to reconcile. If any row
    // names an actor, every row carries the column - null where it has none.
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
    // MySQL's insert-ignore has no `RETURNING`. The grants land either way;
    // `null` says the driver cannot name the new ones, and the engine leaves
    // `changed` off rather than guessing. Finding out would cost a second
    // round trip for an answer nobody asked for.
    if (this._dialect === 'mysql') {
      await this._refusingUnknownRole(() => Promise.resolve(statement))
      return null
    }
    // `r.scope ?? null` compares against the column as stored, which keeps an
    // unscoped row distinct from one scoped to the empty string.
    return creditWrites(
      rows,
      returnedTriples(await this._refusingUnknownRole(() => statement.returning())),
      (r, t) => r.subjectId === t.subjectId && r.roleId === t.roleId && (r.scope ?? null) === t.scope,
    )
  }

  /**
   * Revokes every triple with one `DELETE` whose `WHERE` is an `OR` of the
   * per-triple conditions. Falls back to one delete per row when `ops.or` was
   * not supplied - same rows removed, more statements.
   *
   * Reports which rows this statement actually removed, read off the same
   * `DELETE` via `RETURNING`. A triple that was never granted is still `ok`,
   * mirroring {@link revokeRole}: the postcondition ("this subject does not
   * hold this role here") holds either way. It is reported `changed: false`.
   *
   * @param rows - The triples to revoke. A row with no `scope` revokes the role in every scope.
   * @returns Indices of the rows this call removed a grant for, or `null` on MySQL.
   */
  async revokeRoleMany(rows: readonly IamAdapter.ITripleRow<TRole, TScope>[]): Promise<readonly number[] | null> {
    for (const r of rows) iamAssertAssignableScope('drizzle', r.scope)
    if (rows.length === 0) return []
    const rowCondition = (r: IamAdapter.ITripleRow<TRole, TScope>): SQLWrapper | undefined => {
      const conditions: (SQLWrapper | undefined)[] = [
        this._eq(this._t.assignments.subjectId, r.subjectId) as SQLWrapper,
        this._eq(this._t.assignments.roleId, r.roleId) as SQLWrapper,
      ]
      if (r.scope !== undefined) conditions.push(this._eq(this._t.assignments.scope, r.scope) as SQLWrapper)
      return this._and(...conditions)
    }
    const or = this._or
    const wheres = or ? [or(...rows.map(rowCondition))] : rows.map(rowCondition)

    // MySQL has no `RETURNING` on `DELETE`; see {@link assignRoleMany}.
    if (this._dialect === 'mysql') {
      for (const where of wheres) await this._db.delete(this._t.assignments).where(where)
      return null
    }

    const gone: ReturnedTriple[] = []
    for (const where of wheres) {
      gone.push(...returnedTriples(await this._db.delete(this._t.assignments).where(where).returning()))
    }
    // A requested row with no `scope` revokes the role everywhere, so it
    // accounts for a removed row whatever scope that row held. A scoped
    // request accounts only for its own scope, and `''` is a scope like any
    // other - distinct from the unscoped row's `null`.
    return creditWrites(
      rows,
      gone,
      (r, t) => r.subjectId === t.subjectId && r.roleId === t.roleId && (r.scope === undefined || r.scope === t.scope),
    )
  }

  /**
   * Moves `(subjectId, roleId, fromScope)` to `toScope` with one `UPDATE`. Requires
   * `ops.isNull` (the global/unscoped case needs `IS NULL`, not `eq(col, null)`);
   * without it, or when nothing matches `fromScope`, returns `false` so the engine
   * falls back to revoke + assign.
   */
  async updateAssignmentScope(
    subjectId: string,
    roleId: TRole,
    fromScope: TScope | undefined,
    toScope: TScope | undefined,
    actor?: string,
  ): Promise<boolean> {
    if (!this._isNull) return false
    const table = this._t.assignments as unknown as { subjectId: unknown; roleId: unknown; scope: unknown }
    const scopeCondition = (scope: TScope | undefined) =>
      scope === undefined ? (this._isNull as (col: unknown) => SQLWrapper)(table.scope) : this._eq(table.scope, scope)

    const fromCondition = this._and(
      this._eq(table.subjectId, subjectId) as SQLWrapper,
      this._eq(table.roleId, roleId) as SQLWrapper,
      scopeCondition(fromScope) as SQLWrapper,
    )
    const existing = await this._db.select().from(this._t.assignments).where(fromCondition).limit(1)
    if (!existing[0]) return false

    const toCondition = this._and(
      this._eq(table.subjectId, subjectId) as SQLWrapper,
      this._eq(table.roleId, roleId) as SQLWrapper,
      scopeCondition(toScope) as SQLWrapper,
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
    // No `data === null -> {}` short circuit. `data` is `.notNull()` in all
    // three shipped schemas, so a row that exists cannot carry an absent value
    // - a `null` arriving here is `'null'::jsonb`, a stored value, and the
    // shape an import or a hand-written migration produces from a missing
    // field. Answering `{}` for it read as "this subject has no attributes"
    // and silently retired every deny rule that tests one; prisma's adapter
    // threw on the identical row. `_validateAttributesShape` refuses it.
    return this._validateAttributesShape(data ?? null, subjectId)
  }

  private _validateAttributesShape(value: unknown, subjectId: string): IamPrimitives.Attributes {
    const attrs = iamNarrowAttributes(value)
    if (attrs === null) {
      const got = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value
      this._reportPolicyError(
        new Error(`Attributes for "${subjectId}" must be a JSON object of scalar values (got ${got})`),
        subjectId,
      )
      throw new Error(`[@gentleduck/iam:drizzle] corrupted attributes for "${subjectId}" (not a JSON object)`)
    }
    return attrs
  }

  /**
   * Shallow-merges new attributes into the subject's existing bag (upsert).
   *
   * @param subjectId - Identifies the subject whose attributes are written.
   * @param attrs - Provides the partial attribute patch to merge in.
   * @returns Resolves once the upsert completes.
   */
  async setSubjectAttributes(
    subjectId: string,
    attrs: IamPrimitives.Attributes,
    opts?: IamAdapter.IActorOptions,
  ): Promise<void> {
    // The other four adapters have always called this; without it a non-object
    // `attrs` spreads into per-character keys and corrupts the ABAC bag, so the
    // same call errored loudly on memory/file/redis/http and wrote junk here.
    iamAssertAttributesParam('drizzle', subjectId, attrs)
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
    const who = provenance(opts?.actor)
    await this._upsert(this._t.attrs, { subjectId, data: merged, ...who.insert }, this._t.attrs.subjectId, subjectId, {
      data: merged,
      ...who.update,
    })
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

/**
 * Creates an IamDrizzleAdapter instance from a Drizzle db instance and
 * IamDrizzle table schema.
 *
 * @template TEngine - The access control engine configuration.
 * @template TDb - The Drizzle db instance.
 * @template TType - The Drizzle db dialect.
 * @template Params - The access control engine configuration parameters.
 *
 * @param config - Provides the IamDrizzle db, tables, and operator functions.
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
