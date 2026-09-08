import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../../core/types'
import { parsePolicyRow, parseRoleRow, validatePolicy } from '../../core/validate'
import { iamAssertNoAssignOptions } from '../../shared/assign-options'
import { iamUnknownRoleError } from '../../shared/assignment-target'
import { iamAssertAttributesParam, iamNarrowAttributes } from '../../shared/attributes'
import {
  iamAssertSavablePolicy,
  iamAssertSavableRole,
  iamNormalizePolicy,
  iamUnreadablePolicy,
} from '../../shared/rows'
import { iamAssertAssignableScope } from '../../shared/scope'
import { iamAsRoleLiteral, iamAsScopeLiteral } from '../../shared/tenant-literals'

/** IamPrisma adapter integration types. Type-only namespace - zero bundle cost. */
export namespace IamPrisma {
  /** Row shape returned by `prisma.accessPolicy` queries. */
  export interface IPolicyRow {
    id: string
    name: string
    description: string | null
    version: number
    algorithm: string
    rules: unknown
    targets: unknown | null
  }

  /** Row shape returned by `prisma.accessRole` queries. */
  export interface IRoleRow {
    id: string
    name: string
    description: string | null
    permissions: unknown
    inherits: string[] | null
    scope: string | null
    metadata: unknown | null
  }

  /** Row shape returned by `prisma.accessAssignment` queries. */
  export interface IAssignmentRow {
    subjectId: string
    roleId: string
    scope: string | null
  }

  /** Row shape returned by `prisma.accessSubjectAttr` queries. */
  export interface IAttrRow {
    subjectId: string
    data: unknown
  }

  /**
   * Generic Prisma client type so we don't require @prisma/client as a hard dep.
   * Your PrismaClient just needs these models.
   */
  export interface ILike {
    accessPolicy: {
      findMany: (args?: unknown) => Promise<IPolicyRow[]>
      findUnique: (args: { where: { id: string } }) => Promise<IPolicyRow | null>
      upsert: (args: {
        where: { id: string }
        create: Record<string, unknown>
        update: Record<string, unknown>
      }) => Promise<IPolicyRow>
      /**
       * `deleteMany`, not `delete`: Prisma's `delete` raises `P2025` when
       * nothing matches, so deleting a row that is already gone threw here and
       * no-opped on the other five adapters. An idempotent admin retry must not
       * depend on the backend.
       */
      deleteMany: (args: { where: { id: string } }) => Promise<{ count: number }>
    }
    accessRole: {
      findMany: (args?: unknown) => Promise<IRoleRow[]>
      findUnique: (args: { where: { id: string } }) => Promise<IRoleRow | null>
      upsert: (args: {
        where: { id: string }
        create: Record<string, unknown>
        update: Record<string, unknown>
      }) => Promise<IRoleRow>
      /** See `accessPolicy.deleteMany`. */
      deleteMany: (args: { where: { id: string } }) => Promise<{ count: number }>
    }
    accessAssignment: {
      findMany: (args: {
        where: { subjectId: string; roleId?: string; scope?: string | null }
        take?: number
      }) => Promise<IAssignmentRow[]>
      create: (args: { data: Record<string, unknown> }) => Promise<IAssignmentRow>
      deleteMany: (args: { where: Record<string, unknown> }) => Promise<{ count: number }>
      updateMany: (args: {
        where: Record<string, unknown>
        data: Record<string, unknown>
      }) => Promise<{ count: number }>
    }
    accessSubjectAttr: {
      findUnique: (args: { where: { subjectId: string } }) => Promise<IAttrRow | null>
      upsert: (args: {
        where: { subjectId: string }
        create: Record<string, unknown>
        update: Record<string, unknown>
      }) => Promise<IAttrRow>
    }
  }
}

/**
 * Prisma-backed adapter; expects `accessPolicy`, `accessRole`, `accessAssignment`, `accessSubjectAttr` models.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @template TPrisma - Constrains the Prisma client shape.
 */
/**
 * Provenance columns for an upsert: `created_by` on the row this call inserts,
 * `updated_by` on the row it overwrites. `created_by` answers "who first put
 * this here" and must not move on a later edit; `updated_by` answers "who
 * touched it last" and must. Spread rather than written as null, so a table
 * predating the columns is untouched unless the caller names an actor.
 */
/**
 * Is this Prisma's `P2002`, "unique constraint failed"?
 *
 * `assignRole` is a read-then-write, and the gap between the two statements is
 * exactly wide enough for a concurrent writer to insert the same grant first.
 * The loser's `create` then raised `P2002` and the call rejected - a repeat
 * grant of a role the subject demonstrably holds, reported as a failure, while
 * every other adapter treats one as a no-op (`SADD`, `onConflictDoNothing`,
 * skip-if-present). Twenty concurrent identical scoped grants produced nine
 * rejections before this.
 *
 * Swallowing it is not hiding an error: the row the caller asked for exists,
 * which is the whole of what `assignRole` promises.
 */
function isUniqueConstraintViolation(err: unknown): boolean {
  if (err === null || typeof err !== 'object') return false
  return Reflect.get(err, 'code') === 'P2002'
}

/**
 * Is this Prisma's `P2003`, "foreign key constraint failed"?
 *
 * `schema.prisma` declares `role AccessRole @relation(...)`, so granting a role
 * that is not stored is refused by the database here exactly as it is on
 * drizzle. What differed was the *wording*: drizzle translates its driver error
 * into the shared refusal, and memory / file / redis raise the same sentence
 * from their own lookup, so five adapters said one thing and Prisma leaked
 * ``Foreign key constraint failed on the field: `roleId` `` straight from the
 * driver. A caller cannot branch on that, and it names a column of a schema the
 * operator did not necessarily write.
 *
 * Prisma's own code is checked rather than {@link iamIsForeignKeyViolation}'s
 * message text: `P2003` is unambiguous and does not move with the server's
 * locale, and `roleId` is the only relation on the assignment model, so there
 * is no other constraint this could be.
 */
function isForeignKeyViolation(err: unknown): boolean {
  if (err === null || typeof err !== 'object') return false
  return Reflect.get(err, 'code') === 'P2003'
}

function provenance(actor: string | undefined): {
  create: Record<string, string>
  update: Record<string, string>
} {
  if (actor === undefined) return { create: {}, update: {} }
  return { create: { createdBy: actor }, update: { updatedBy: actor } }
}

/**
 * Backs the engine with Prisma models. Structurally typed against
 * {@link IamPrisma.ILike} rather than importing `@prisma/client`, so the
 * generated client - which every project generates differently - stays out of
 * this package's dependency graph, and a transaction handle (`tx`) is accepted
 * wherever the base client is.
 *
 * Rows are validated on the way out, never trusted: a policy or role row that
 * fails to parse is reported through `onPolicyError` and replaced with an
 * unreadable placeholder that grants nothing, so one corrupt row degrades to a
 * denial instead of taking down every check that loads the table.
 *
 * @example
 * ```ts
 * const engine = new IamEngine({ adapter: new IamPrismaAdapter(prisma) })
 *
 * await prisma.$transaction(async (tx) => {
 *   const scoped = new IamPrismaAdapter(prisma).withClient(tx)
 *   await scoped.createRole(role)
 * })
 * ```
 */
export class IamPrismaAdapter<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
  TPrisma extends IamPrisma.ILike = IamPrisma.ILike,
> implements IamAdapter.IAdapter<TAction, TResource, TRole, TScope>
{
  private _prisma: TPrisma

  /**
   * Creates a new Prisma adapter.
   *
   * @param prisma - Provides the Prisma client instance with required models.
   */
  constructor(prisma: TPrisma) {
    this._prisma = prisma
  }

  /**
   * Re-makes this adapter against `client` - the value Prisma hands an
   * interactive transaction callback, `$transaction(async (tx) => ...)`.
   *
   * That `tx` exposes the same delegates (`accessPolicy`, `accessRole`, ...)
   * as the base client, minus `$transaction` itself, so every read and write
   * this adapter makes joins the caller's transaction unchanged.
   */
  withClient(client: unknown): IamPrismaAdapter<TAction, TResource, TRole, TScope, TPrisma> {
    return new IamPrismaAdapter<TAction, TResource, TRole, TScope, TPrisma>(client as TPrisma)
  }

  /**
   * Lists every policy in the database.
   *
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns All policies parsed from `accessPolicy` rows.
   */
  async listPolicies(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IPolicy<TAction, TResource, TRole>[]> {
    const rows = await this._prisma.accessPolicy.findMany()
    const out: AccessControl.IPolicy<TAction, TResource, TRole>[] = []
    for (const row of rows) out.push(this._readPolicy(row))
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
    const row = await this._prisma.accessPolicy.findUnique({ where: { id } })
    return row ? this._readPolicy(row) : null
  }

  /**
   * One policy row, or a throw naming it.
   *
   * This adapter used to be alone in dropping an unreadable policy row with no
   * signal at all - the other five at least warn - so a corrupt row removed a
   * policy and nothing said so. See {@link iamUnreadablePolicy} for why a
   * policy is refused where a role is skipped.
   *
   * Reported through `console.warn` rather than an `onPolicyError` handler:
   * unlike the other adapters this one takes no options object, so there is
   * nowhere to wire one without changing its constructor. The throw is the part
   * that matters for correctness; the warning names the row.
   */
  private _readPolicy(row: IamPrisma.IPolicyRow): AccessControl.IPolicy<TAction, TResource, TRole> {
    const candidate = toPolicy(row)
    const policy = parsePolicyRow<TAction, TResource, TRole>(candidate)
    if (policy !== null) return policy
    const issues = validatePolicy(candidate)
      .issues.map((i) => i.message)
      .join('; ')
    console.warn(`[@gentleduck/iam:prisma] unreadable policy row "${row.id}": ${issues}`)
    throw iamUnreadablePolicy('prisma', row.id, issues)
  }

  /**
   * Upserts a policy through Prisma.
   *
   * @param p - Provides the policy to persist.
   * @returns Resolves once the upsert completes.
   */
  async savePolicy(
    p: AccessControl.IPolicy<TAction, TResource, TRole>,
    opts?: IamAdapter.IActorOptions,
  ): Promise<void> {
    iamAssertSavablePolicy('prisma', p)
    const data = fromPolicy(iamNormalizePolicy(p))
    const who = provenance(opts?.actor)
    await this._prisma.accessPolicy.upsert({
      where: { id: p.id },
      create: { ...data, ...who.create },
      update: { ...data, ...who.update },
    })
  }

  /**
   * Removes a policy by ID.
   *
   * @param id - Identifies the policy to delete.
   * @returns Resolves once the delete completes.
   */
  async deletePolicy(id: string): Promise<void> {
    await this._prisma.accessPolicy.deleteMany({ where: { id } })
  }

  /**
   * Lists every role in the database.
   *
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns All roles parsed from `accessRole` rows.
   */
  async listRoles(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope>[]> {
    const rows = await this._prisma.accessRole.findMany()
    const out: AccessControl.IRole<TAction, TResource, TRole, TScope>[] = []
    for (const row of rows) {
      const role = parseRoleRow<TAction, TResource, TRole, TScope>(toRole(row))
      if (role !== null) out.push(role)
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
    const row = await this._prisma.accessRole.findUnique({ where: { id } })
    return row ? parseRoleRow<TAction, TResource, TRole, TScope>(toRole(row)) : null
  }

  /**
   * Upserts a role through Prisma.
   *
   * @param r - Provides the role to persist.
   * @returns Resolves once the upsert completes.
   */
  async saveRole(
    r: AccessControl.IRole<TAction, TResource, TRole, TScope>,
    opts?: IamAdapter.IActorOptions,
  ): Promise<void> {
    iamAssertSavableRole('prisma', r)
    const data = fromRole(r)
    const who = provenance(opts?.actor)
    await this._prisma.accessRole.upsert({
      where: { id: r.id },
      create: { ...data, ...who.create },
      update: { ...data, ...who.update },
    })
  }

  /**
   * Removes a role by ID.
   *
   * @param id - Identifies the role to delete.
   * @returns Resolves once the delete completes.
   */
  async deleteRole(id: string): Promise<void> {
    await this._prisma.accessRole.deleteMany({ where: { id } })
  }

  /**
   * Lists deduplicated role IDs assigned to a subject (scoped or unscoped).
   *
   * @param subjectId - Identifies the subject whose roles are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns Deduplicated array of role IDs.
   */
  async getSubjectRoles(subjectId: string, _opts?: IamAdapter.IReadOptions): Promise<TRole[]> {
    // Unscoped (global) roles only. Scoped assignments are surfaced
    // separately via getSubjectScopedRoles.
    const rows = await this._prisma.accessAssignment.findMany({
      where: { subjectId, scope: null },
    })
    return [...new Set(rows.map((r) => iamAsRoleLiteral<TRole>(r.roleId)))]
  }

  /**
   * Lists scoped role assignments for a subject.
   *
   * @param subjectId - Identifies the subject whose scoped roles are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns Array of `(role, scope)` pairs for scoped assignments only.
   */
  async getSubjectScopedRoles(
    subjectId: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<IamRequest.IScopedRole<TRole, TScope>[]> {
    const rows = await this._prisma.accessAssignment.findMany({
      where: { subjectId },
    })
    // Narrowed per row, not by a `filter` predicate the mapper cannot see: the
    // old `r.scope as TScope` let a `null` scope through as a scope value the
    // moment the predicate changed.
    const out: IamRequest.IScopedRole<TRole, TScope>[] = []
    for (const r of rows) {
      if (r.scope === null || r.scope === undefined) continue
      out.push({ role: iamAsRoleLiteral<TRole>(r.roleId), scope: iamAsScopeLiteral<TScope>(r.scope) })
    }
    return out
  }

  /**
   * Grants a role to a subject, optionally restricted to a scope.
   *
   * A grant naming a role that does not exist is refused by the FK on
   * `AccessAssignment.role`, which raises before the row lands; the other
   * adapters check explicitly to reach the same answer.
   *
   * @param subjectId - Identifies the subject receiving the role.
   * @param roleId - Specifies the role being granted.
   * @param scope - Optional scope binding the assignment.
   * @returns Resolves once the row is inserted.
   */
  async assignRole(subjectId: string, roleId: TRole, scope?: TScope, opts?: IamAdapter.IAssignOptions): Promise<void> {
    iamAssertAssignableScope('prisma', scope)
    iamAssertNoAssignOptions('prisma', opts)
    // Idempotent, like the other five adapters: memory and file skip an
    // existing pair, redis uses `SADD`, drizzle uses `onConflictDoNothing`.
    // A bare `create` against the `@@unique([subjectId, roleId, scope])` index
    // raised `P2002` for a repeat *scoped* grant, so re-running a provisioning
    // script failed on Prisma alone - and for an *unscoped* one it did not even
    // do that, because SQL unique indexes do not collapse `NULL`s, so the row
    // was inserted again and the table grew without bound.
    //
    // A read-then-write, not an `upsert`: the composite key includes a nullable
    // column, and `upsert` cannot address a row whose key is partly `NULL`.
    // It is the fast path only - the read cannot make the write atomic, so a
    // concurrent writer can still land the same grant in the window between
    // them, and the unique index is what actually decides the outcome. That
    // index has to be the `NULLS NOT DISTINCT` one `schema.prisma` tells you to
    // migrate to; the plain index Prisma generates does not collapse `NULL`s,
    // so unscoped duplicates pile up unchecked.
    const existing = await this._prisma.accessAssignment.findMany({
      take: 1,
      where: { roleId, scope: scope ?? null, subjectId },
    })
    if (existing.length > 0) return
    try {
      await this._prisma.accessAssignment.create({
        data: { roleId, scope: scope ?? null, subjectId, ...provenance(opts?.actor).create },
      })
    } catch (err) {
      // The role does not exist. Translated rather than propagated so the
      // refusal reads the same on every adapter - see `iamUnknownRoleError`.
      // The driver error is kept as `cause`, so nothing is lost.
      if (isForeignKeyViolation(err)) throw iamUnknownRoleError('prisma', err)
      // The row exists - a racing writer inserted the identical grant first.
      // That is the state the caller asked for, so this is a success. Any
      // other failure is real and propagates.
      if (!isUniqueConstraintViolation(err)) throw err
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
    iamAssertAssignableScope('prisma', scope)
    await this._prisma.accessAssignment.deleteMany({
      where: { subjectId, roleId, ...(scope !== undefined ? { scope } : {}) },
    })
  }

  /**
   * Moves an existing assignment to a different scope in place, preserving its row
   * (`id`, `createdAt`) instead of a delete + create.
   *
   * @param subjectId - Identifies the subject whose assignment is moving.
   * @param roleId - Specifies the role of the assignment being moved.
   * @param fromScope - The assignment's current scope.
   * @param toScope - The scope to move it to.
   * @returns `false` when no `(subjectId, roleId, fromScope)` row exists.
   */
  async updateAssignmentScope(
    subjectId: string,
    roleId: TRole,
    fromScope?: TScope,
    toScope?: TScope,
    actor?: string,
  ): Promise<boolean> {
    // Confirm the source row exists before touching the target scope, otherwise a
    // stale `fromScope` would delete the grant the caller is moving onto.
    const existing = await this._prisma.accessAssignment.findMany({
      where: { subjectId, roleId, scope: fromScope ?? null },
      take: 1,
    })
    if (existing.length === 0) return false
    // The target scope may already have its own row (unique on subjectId+roleId+scope);
    // drop it rather than let the update violate that constraint.
    //
    // No `NOT: { scope: from }` guarding the source row. That clause was there
    // for the no-op move, but on a nullable column it is three-valued logic:
    // moving `org-1` to global asked for `scope IS NULL AND NOT (scope =
    // 'org-1')`, whose second half is `NULL` for exactly the rows the first
    // half selected, so the global row was never deleted and the update left
    // two of them - the collapse this delete exists to perform, silently
    // skipped. Comparing the two scopes here settles the no-op case in
    // JavaScript, where `null` compares the way it reads.
    const from = fromScope ?? null
    const to = toScope ?? null
    if (from !== to) {
      await this._prisma.accessAssignment.deleteMany({
        where: { subjectId, roleId, scope: to },
      })
    }
    const result = await this._prisma.accessAssignment.updateMany({
      where: { subjectId, roleId, scope: fromScope ?? null },
      data: { scope: toScope ?? null, ...provenance(actor).update },
    })
    return result.count > 0
  }

  /**
   * Fetches the attribute bag stored for a subject.
   *
   * @param subjectId - Identifies the subject whose attributes are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns The subject's attributes or `{}` when none are recorded.
   */
  async getSubjectAttributes(subjectId: string, _opts?: IamAdapter.IReadOptions): Promise<IamPrimitives.Attributes> {
    const row = await this._prisma.accessSubjectAttr.findUnique({
      where: { subjectId },
    })
    if (!row) return {}
    const data = row.data
    // `iamNarrowAttributes` builds a fresh Record, so this also avoids sharing
    // the Prisma-managed object.
    const attrs = iamNarrowAttributes(data)
    if (attrs === null) {
      throw new Error(
        `[@gentleduck/iam:prisma] corrupted attributes for "${subjectId}" (expected a JSON object of scalar values, got ${
          data === null ? 'null' : Array.isArray(data) ? 'array' : typeof data
        })`,
      )
    }
    return attrs
  }

  /**
   * Shallow-merges new attributes into the subject's existing bag via upsert.
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
    iamAssertAttributesParam('prisma', subjectId, attrs)
    // Recover from corrupt existing data instead of locking the operator out -
    // but say so. Redis and drizzle route the same swallow through
    // `onPolicyError`; this one said nothing at all, so a read that failed for
    // any reason, a transient connection error included, silently replaced the
    // subject's whole attribute bag with the keys in this call. The overwrite
    // still happens (the alternative is an operator locked out by one corrupt
    // row) and now it leaves a record. `console.warn` because this adapter has
    // no error handler to wire - the same reason `_readPolicy` uses it.
    let existing: IamPrimitives.Attributes
    try {
      existing = await this.getSubjectAttributes(subjectId)
    } catch (err) {
      console.warn(
        `[@gentleduck/iam:prisma] could not read existing attributes for "${subjectId}"; ` +
          `overwriting with the attributes in this call: ${err instanceof Error ? err.message : String(err)}`,
      )
      existing = {}
    }
    const merged = { ...existing, ...attrs }
    const who = provenance(opts?.actor)
    await this._prisma.accessSubjectAttr.upsert({
      where: { subjectId },
      create: { subjectId, data: merged, ...who.create },
      update: { data: merged, ...who.update },
    })
  }
}

/**
 * Reshapes a {@link IamPrisma.IPolicyRow} into a policy *candidate*.
 *
 * The return type is deliberately not `AccessControl.IPolicy`: `rules`,
 * `targets` and `algorithm` are Prisma `Json` columns holding whatever was
 * written to the row, and this function does no checking. It used to claim the
 * domain type by asserting each column into it, which put the lie one call
 * earlier than the validation - every caller pipes the result through
 * `parsePolicyRow`, and that is what decides the row is a policy.
 */
function toPolicy(row: IamPrisma.IPolicyRow): Record<string, unknown> {
  return {
    id: row.id,
    name: row.name,
    ...(row.description === null || row.description === undefined ? {} : { description: row.description }),
    version: row.version,
    algorithm: row.algorithm,
    rules: row.rules,
    ...(row.targets === null || row.targets === undefined ? {} : { targets: row.targets }),
  }
}

/** Converts a {@link AccessControl.IPolicy} domain object into a flat record suitable for Prisma create/update. */
function fromPolicy(p: AccessControl.IPolicy): Record<string, unknown> {
  return {
    id: p.id,
    name: p.name,
    description: p.description ?? null,
    version: p.version ?? 1,
    algorithm: p.algorithm,
    rules: p.rules,
    targets: p.targets ?? null,
  }
}

/** Role candidate, on the same terms as {@link toPolicy} - unchecked, and typed to say so. */
function toRole(row: IamPrisma.IRoleRow): Record<string, unknown> {
  // Absent columns are omitted, not set to `undefined` - the shape
  // `IamDrizzleAdapter._safeParseRole` already produces, and the one the other
  // stores return by handing back the caller's own object. A key holding
  // `undefined` is still a key: `Object.keys` lists it, `JSON.stringify` drops
  // it and `toEqual` ignores it, so "does this role have a description" got
  // three answers depending which one the consumer asked, and a role saved as
  // `{id, name, permissions}` read back from prisma with seven keys and from
  // memory with three.
  //
  // `inherits: []` is the same case wearing a different coat: it was invented
  // here for a role that never had one, so a round trip through prisma turned
  // an absent `inherits` into an empty array. Drizzle drops the empty value for
  // exactly that reason, and `RoleBuilder.build()` omits the key when the
  // author sets no parents, so absent is the shape both ends already agree on.
  const inherits: unknown = row.inherits
  return {
    id: row.id,
    name: row.name,
    ...(row.description === null || row.description === undefined ? {} : { description: row.description }),
    permissions: row.permissions,
    // Anything that is not an empty array is passed through unchanged, including
    // values that are not arrays at all, so `parseRoleRow` still sees - and
    // refuses - a corrupt column rather than having it quietly normalised away.
    ...(inherits === null || inherits === undefined || (Array.isArray(inherits) && inherits.length === 0)
      ? {}
      : { inherits }),
    ...(row.scope === null || row.scope === undefined ? {} : { scope: row.scope }),
    ...(row.metadata === null || row.metadata === undefined ? {} : { metadata: row.metadata }),
  }
}

/** Converts a {@link AccessControl.IRole} domain object into a flat record suitable for Prisma create/update. */
function fromRole(r: AccessControl.IRole): Record<string, unknown> {
  return {
    id: r.id,
    name: r.name,
    description: r.description ?? null,
    permissions: r.permissions,
    inherits: r.inherits ?? [],
    scope: r.scope ?? null,
    metadata: r.metadata ?? null,
  }
}

/** Factory around {@link IamPrismaAdapter}, for callers who prefer functions to `new`. */
export function iamPrismaAdapter(...args: ConstructorParameters<typeof IamPrismaAdapter>): IamPrismaAdapter {
  return new IamPrismaAdapter(...args)
}
