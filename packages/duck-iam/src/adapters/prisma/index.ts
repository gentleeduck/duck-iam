import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../../core/types'
import { parsePolicyRow, parseRoleRow } from '../../core/validate'
import { iamAssertNoAssignOptions } from '../../shared/assign-options'
import { iamAssertAttributesParam, iamNarrowAttributes } from '../../shared/attributes'
import { iamAssertSavablePolicy, iamAssertSavableRole, iamNormalizePolicy } from '../../shared/rows'
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
    for (const row of rows) {
      const policy = parsePolicyRow<TAction, TResource, TRole>(toPolicy(row))
      if (policy !== null) out.push(policy)
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
    const row = await this._prisma.accessPolicy.findUnique({ where: { id } })
    return row ? parsePolicyRow<TAction, TResource, TRole>(toPolicy(row)) : null
  }

  /**
   * Upserts a policy through Prisma.
   *
   * @param p - Provides the policy to persist.
   * @returns Resolves once the upsert completes.
   */
  async savePolicy(p: AccessControl.IPolicy<TAction, TResource, TRole>): Promise<void> {
    iamAssertSavablePolicy('prisma', p)
    const data = fromPolicy(iamNormalizePolicy(p))
    await this._prisma.accessPolicy.upsert({
      where: { id: p.id },
      create: data,
      update: data,
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
  async saveRole(r: AccessControl.IRole<TAction, TResource, TRole, TScope>): Promise<void> {
    iamAssertSavableRole('prisma', r)
    const data = fromRole(r)
    await this._prisma.accessRole.upsert({
      where: { id: r.id },
      create: data,
      update: data,
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
    // The window between the two statements is the same one every other adapter
    // has; if a concurrent writer wins it, the unique index rejects the insert
    // for a scoped grant, which is the correct outcome for a duplicate.
    const existing = await this._prisma.accessAssignment.findMany({
      take: 1,
      where: { roleId, scope: scope ?? null, subjectId },
    })
    if (existing.length > 0) return
    await this._prisma.accessAssignment.create({
      data: { roleId, scope: scope ?? null, subjectId },
    })
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
    // Accepted for contract parity with the other adapters; the reference Prisma
    // schema has no `updatedBy` column so there is nothing to persist it to.
    _actor?: string,
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
    await this._prisma.accessAssignment.deleteMany({
      where: { subjectId, roleId, scope: toScope ?? null, NOT: { scope: fromScope ?? null } },
    })
    const result = await this._prisma.accessAssignment.updateMany({
      where: { subjectId, roleId, scope: fromScope ?? null },
      data: { scope: toScope ?? null },
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
  async setSubjectAttributes(subjectId: string, attrs: IamPrimitives.Attributes): Promise<void> {
    // The other four adapters have always called this; without it a non-object
    // `attrs` spreads into per-character keys and corrupts the ABAC bag, so the
    // same call errored loudly on memory/file/redis/http and wrote junk here.
    iamAssertAttributesParam('prisma', subjectId, attrs)
    // Recover from corrupt existing data instead of locking the operator out.
    let existing: IamPrimitives.Attributes
    try {
      existing = await this.getSubjectAttributes(subjectId)
    } catch {
      existing = {}
    }
    const merged = { ...existing, ...attrs }
    await this._prisma.accessSubjectAttr.upsert({
      where: { subjectId },
      create: { subjectId, data: merged },
      update: { data: merged },
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
  return {
    id: row.id,
    name: row.name,
    description: row.description ?? undefined,
    permissions: row.permissions,
    inherits: row.inherits ?? [],
    scope: row.scope ?? undefined,
    metadata: row.metadata ?? undefined,
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
