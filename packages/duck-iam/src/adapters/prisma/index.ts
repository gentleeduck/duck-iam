import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../../core/types'
import { parsePolicyRow, parseRoleRow, validatePolicy, validateRole } from '../../core/validate'
import { iamAssertNoAssignOptions } from '../../shared/assign-options'
import { iamUnknownRoleError } from '../../shared/assignment-target'
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

  /** Structural Prisma client shape, so `@prisma/client` is not a dependency; your client needs these models. */
  export interface ILike {
    accessPolicy: {
      findMany: (args?: unknown) => Promise<IPolicyRow[]>
      findUnique: (args: { where: { id: string } }) => Promise<IPolicyRow | null>
      upsert: (args: {
        where: { id: string }
        create: Record<string, unknown>
        update: Record<string, unknown>
      }) => Promise<IPolicyRow>
      /** NOTE: `deleteMany`, not `delete`: `delete` throws `P2025` when nothing matches, and deletes are idempotent. */
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
 * Is this Prisma's `P2002` (unique constraint failed)?
 * NOTE: `assignRole` reads then writes, so a concurrent identical grant can win; its `P2002` means the row exists.
 */
function isUniqueConstraintViolation(err: unknown): boolean {
  if (err === null || typeof err !== 'object') return false
  return Reflect.get(err, 'code') === 'P2002'
}

/**
 * Is this Prisma's `P2003` (foreign key constraint failed)?
 * Checks the code, not the locale-dependent message; `roleId` is the assignment model's only relation.
 */
function isForeignKeyViolation(err: unknown): boolean {
  if (err === null || typeof err !== 'object') return false
  return Reflect.get(err, 'code') === 'P2003'
}

/**
 * Provenance columns for an upsert: `createdBy` on create, `updatedBy` on update.
 * Empty when no actor is named, so a table without the columns is untouched.
 */
function provenance(actor: string | undefined): {
  create: Record<string, string>
  update: Record<string, string>
} {
  if (actor === undefined) return { create: {}, update: {} }
  return { create: { createdBy: actor }, update: { updatedBy: actor } }
}

/**
 * Prisma-backed adapter; expects `accessPolicy`, `accessRole`, `accessAssignment`, `accessSubjectAttr` models.
 * SECURITY: a malformed role row is warned and skipped; a malformed policy row is warned and throws.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @template TPrisma - Constrains the Prisma client shape.
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

  /** @param prisma - A Prisma client or transaction handle with the {@link IamPrisma.ILike} models. */
  constructor(prisma: TPrisma) {
    this._prisma = prisma
  }

  /** Re-creates this adapter on `client`, e.g. the `tx` from `$transaction(async (tx) => ...)`. */
  withClient(client: unknown): IamPrismaAdapter<TAction, TResource, TRole, TScope, TPrisma> {
    return new IamPrismaAdapter<TAction, TResource, TRole, TScope, TPrisma>(client as TPrisma)
  }

  /** Lists every policy; throws if any policy row is unreadable. */
  async listPolicies(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IPolicy<TAction, TResource, TRole>[]> {
    const rows = await this._prisma.accessPolicy.findMany()
    const out: AccessControl.IPolicy<TAction, TResource, TRole>[] = []
    for (const row of rows) out.push(this._readPolicy(row))
    return out
  }

  /** Fetches a policy by ID, or `null` when absent. */
  async getPolicy(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IPolicy<TAction, TResource, TRole> | null> {
    const row = await this._prisma.accessPolicy.findUnique({ where: { id } })
    return row ? this._readPolicy(row) : null
  }

  /**
   * Parses one policy row, or warns and throws naming it. See {@link iamUnreadablePolicy} for why policies are refused.
   * NOTE: `console.warn`, not an `onPolicyError` handler, because this adapter takes no options object.
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

  /** Upserts a policy; `opts.actor` fills `created_by` on create and `updated_by` on update. */
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

  /** Removes a policy by ID; a missing row is a no-op. */
  async deletePolicy(id: string): Promise<void> {
    await this._prisma.accessPolicy.deleteMany({ where: { id } })
  }

  /** Lists every role; throws if any role row is unreadable. */
  async listRoles(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope>[]> {
    const rows = await this._prisma.accessRole.findMany()
    const out: AccessControl.IRole<TAction, TResource, TRole, TScope>[] = []
    for (const row of rows) out.push(this._readRole(row))
    return out
  }

  /** Parses one role row, or warns naming it and throws. See {@link iamUnreadableRole} for why it is not skipped. */
  private _readRole(row: IamPrisma.IRoleRow): AccessControl.IRole<TAction, TResource, TRole, TScope> {
    const candidate = toRole(row)
    const role = parseRoleRow<TAction, TResource, TRole, TScope>(candidate)
    if (role !== null) return role
    const issues = validateRole(candidate)
      .issues.map((i) => i.message)
      .join('; ')
    console.warn(`[@gentleduck/iam:prisma] unreadable role row "${row.id}": ${issues}`)
    throw iamUnreadableRole('prisma', row.id, issues)
  }

  /** Fetches a role by ID, or `null` when absent. Throws (via {@link iamUnreadableRole}) when the row is unreadable. */
  async getRole(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope> | null> {
    const row = await this._prisma.accessRole.findUnique({ where: { id } })
    return row ? this._readRole(row) : null
  }

  /** Upserts a role; `opts.actor` fills `created_by` on create and `updated_by` on update. */
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
   * Removes a role by ID and every `inherits` edge pointing at it; a missing row is a no-op.
   * SECURITY: an orphan edge re-attaches to a role recreated under the same id, as an orphan grant would.
   */
  async deleteRole(id: string): Promise<void> {
    await this._prisma.accessRole.deleteMany({ where: { id } })
    for (const row of await this._prisma.accessRole.findMany()) {
      const role = this._readRole(row)
      const stripped = iamRoleWithoutInherit(role, id)
      if (stripped === null) continue
      const data = fromRole(stripped)
      await this._prisma.accessRole.upsert({ create: data, update: data, where: { id: stripped.id } })
    }
  }

  /** Deduplicated IDs of the subject's *unscoped* roles; scoped ones come from `getSubjectScopedRoles`. */
  async getSubjectRoles(subjectId: string, _opts?: IamAdapter.IReadOptions): Promise<TRole[]> {
    const rows = await this._prisma.accessAssignment.findMany({
      where: { subjectId, scope: null },
    })
    return [...new Set(rows.map((r) => iamAsRoleLiteral<TRole>(r.roleId)))]
  }

  /** The subject's scoped assignments as `(role, scope)` pairs; unscoped rows are excluded. */
  async getSubjectScopedRoles(
    subjectId: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<IamRequest.IScopedRole<TRole, TScope>[]> {
    const rows = await this._prisma.accessAssignment.findMany({
      where: { subjectId },
    })
    // Narrow per row, not with a `filter` predicate the mapper cannot see, so a `null` never passes as a scope.
    const out: IamRequest.IScopedRole<TRole, TScope>[] = []
    for (const r of rows) {
      if (r.scope === null || r.scope === undefined) continue
      out.push({ role: iamAsRoleLiteral<TRole>(r.roleId), scope: iamAsScopeLiteral<TScope>(r.scope) })
    }
    return out
  }

  /**
   * Grants a role, optionally scoped; a repeat grant is a no-op. Only `opts.actor` is supported.
   * An unknown role is refused by the `AccessAssignment.role` FK and reported with the shared unknown-role error.
   */
  async assignRole(subjectId: string, roleId: TRole, scope?: TScope, opts?: IamAdapter.IAssignOptions): Promise<void> {
    iamAssertAssignableScope('prisma', scope)
    iamAssertNoAssignOptions('prisma', opts)
    // Read-then-write, not `upsert`: `upsert` cannot address a composite key with a `NULL` part.
    // WARN: the read is not atomic; racing unscoped grants need the `NULLS NOT DISTINCT` index from `schema.prisma`.
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
      // Unknown role: translate so the refusal reads the same on every adapter (driver error kept as `cause`).
      if (isForeignKeyViolation(err)) throw iamUnknownRoleError('prisma', err)
      // A racing writer inserted the same grant first; the row exists, so this is success.
      if (!isUniqueConstraintViolation(err)) throw err
    }
  }

  /** Removes the subject's assignment of `roleId`; with no `scope`, removes it in every scope. */
  async revokeRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void> {
    iamAssertAssignableScope('prisma', scope, 'lookup')
    await this._prisma.accessAssignment.deleteMany({
      where: { subjectId, roleId, ...(scope !== undefined ? { scope } : {}) },
    })
  }

  /**
   * Moves an assignment to another scope in place, keeping its row (`id`, `createdAt`).
   * @returns `false` when no `(subjectId, roleId, fromScope)` row exists.
   */
  async updateAssignmentScope(
    subjectId: string,
    roleId: TRole,
    fromScope?: TScope,
    toScope?: TScope,
    actor?: string,
  ): Promise<boolean> {
    iamAssertAssignableScope('prisma', fromScope, 'lookup')
    iamAssertAssignableScope('prisma', toScope)
    // Confirm the source row exists first, or a stale `fromScope` would delete the grant being moved onto.
    const existing = await this._prisma.accessAssignment.findMany({
      where: { subjectId, roleId, scope: fromScope ?? null },
      take: 1,
    })
    if (existing.length === 0) return false
    // Drop any existing target row so the update does not violate the unique index.
    // NOTE: scopes compare in JS; `NOT: { scope: from }` evaluates to `NULL` for a global target in SQL.
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
   * The subject's attribute bag, or `{}` when none is stored.
   * SECURITY: a corrupt bag throws, so the engine fails closed.
   */
  async getSubjectAttributes(subjectId: string, _opts?: IamAdapter.IReadOptions): Promise<IamPrimitives.Attributes> {
    const stored = await this._readStoredAttributes(subjectId)
    if (!stored.ok) {
      throw new Error(
        `[@gentleduck/iam:prisma] corrupted attributes for "${subjectId}" (expected a JSON object of scalar values, got ${stored.got})`,
      )
    }
    return stored.attrs
  }

  /** Reads and narrows the stored bag: a failed query rejects, a corrupt row resolves `{ ok: false }`. */
  private async _readStoredAttributes(
    subjectId: string,
  ): Promise<
    { readonly ok: true; readonly attrs: IamPrimitives.Attributes } | { readonly ok: false; readonly got: string }
  > {
    const row = await this._prisma.accessSubjectAttr.findUnique({
      where: { subjectId },
    })
    if (!row) return { ok: true, attrs: {} }
    const data = row.data
    // `iamNarrowAttributes` builds a fresh object, so the Prisma-managed one is never shared.
    const attrs = iamNarrowAttributes(data)
    if (attrs === null) {
      return { ok: false, got: data === null ? 'null' : Array.isArray(data) ? 'array' : typeof data }
    }
    return { ok: true, attrs }
  }

  /** Shallow-merges `attrs` into the subject's stored bag (upsert); a corrupt stored bag is warned and replaced. */
  async setSubjectAttributes(
    subjectId: string,
    attrs: IamPrimitives.Attributes,
    opts?: IamAdapter.IActorOptions,
  ): Promise<void> {
    // Refuse a non-object `attrs`, which would spread into per-character keys.
    iamAssertAttributesParam('prisma', subjectId, attrs)
    // Only a corrupt bag is overwritten; a failed read propagates instead of replacing the bag.
    const stored = await this._readStoredAttributes(subjectId)
    if (!stored.ok) {
      console.warn(
        `[@gentleduck/iam:prisma] existing attributes for "${subjectId}" are corrupt ` +
          `(expected a JSON object of scalar values, got ${stored.got}); overwriting with the attributes in this call`,
      )
    }
    const existing = stored.ok ? stored.attrs : {}
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
 * Reshapes a {@link IamPrisma.IPolicyRow} into an unchecked policy candidate for `parsePolicyRow`.
 * NOTE: not typed `IPolicy`, because the columns hold whatever was written and nothing here checks them.
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
  // Omit absent columns instead of writing `undefined`, so every adapter reads a role back with the same keys.
  // An empty `inherits` counts as absent too, matching drizzle and `RoleBuilder.build()`.
  const inherits: unknown = row.inherits
  return {
    id: row.id,
    name: row.name,
    ...(row.description === null || row.description === undefined ? {} : { description: row.description }),
    permissions: row.permissions,
    // Any other value, even a non-array, passes through so `parseRoleRow` refuses a corrupt column.
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
