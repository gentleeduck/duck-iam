import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../../core/types'
import { parsePolicyRow, parseRoleRow } from '../../core/validate'

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
      delete: (args: { where: { id: string } }) => Promise<IPolicyRow>
    }
    accessRole: {
      findMany: (args?: unknown) => Promise<IRoleRow[]>
      findUnique: (args: { where: { id: string } }) => Promise<IRoleRow | null>
      upsert: (args: {
        where: { id: string }
        create: Record<string, unknown>
        update: Record<string, unknown>
      }) => Promise<IRoleRow>
      delete: (args: { where: { id: string } }) => Promise<IRoleRow>
    }
    accessAssignment: {
      findMany: (args: { where: { subjectId: string; scope?: string | null } }) => Promise<IAssignmentRow[]>
      create: (args: { data: Record<string, unknown> }) => Promise<IAssignmentRow>
      deleteMany: (args: { where: Record<string, unknown> }) => Promise<{ count: number }>
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
    const data = fromPolicy(p)
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
    await this._prisma.accessPolicy.delete({ where: { id } })
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
    await this._prisma.accessRole.delete({ where: { id } })
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
    return [...new Set(rows.map((r) => r.roleId as TRole))]
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
    return rows.filter((r) => r.scope != null).map((r) => ({ role: r.roleId as TRole, scope: r.scope as TScope }))
  }

  /**
   * Grants a role to a subject, optionally restricted to a scope.
   *
   * @param subjectId - Identifies the subject receiving the role.
   * @param roleId - Specifies the role being granted.
   * @param scope - Optional scope binding the assignment.
   * @returns Resolves once the row is inserted.
   */
  async assignRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void> {
    await this._prisma.accessAssignment.create({
      data: { subjectId, roleId, scope: scope ?? null },
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
    await this._prisma.accessAssignment.deleteMany({
      where: { subjectId, roleId, ...(scope ? { scope } : {}) },
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
    const row = await this._prisma.accessSubjectAttr.findUnique({
      where: { subjectId },
    })
    if (!row) return {}
    const data = row.data
    if (typeof data !== 'object' || data === null || Array.isArray(data)) {
      throw new Error(
        `[@gentleduck/iam:prisma] corrupted attributes for "${subjectId}" (expected JSON object, got ${
          data === null ? 'null' : Array.isArray(data) ? 'array' : typeof data
        })`,
      )
    }
    // Reconstruct as a fresh Record to avoid sharing the Prisma-managed object.
    const attrs: IamPrimitives.Attributes = {}
    for (const [k, v] of Object.entries(data)) {
      attrs[k] = v as IamPrimitives.AttributeValue
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

/** Converts a {@link IamPrisma.IPolicyRow} database row into a {@link AccessControl.IPolicy} domain object. */
function toPolicy(row: IamPrisma.IPolicyRow): AccessControl.IPolicy {
  return {
    id: row.id,
    name: row.name,
    description: row.description ?? undefined,
    version: row.version,
    algorithm: row.algorithm as AccessControl.IPolicy['algorithm'],
    rules: row.rules as AccessControl.IPolicy['rules'],
    targets: (row.targets as AccessControl.IPolicy['targets']) ?? undefined,
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

/** Converts a {@link IamPrisma.IRoleRow} database row into a {@link AccessControl.IRole} domain object. */
function toRole(row: IamPrisma.IRoleRow): AccessControl.IRole {
  return {
    id: row.id,
    name: row.name,
    description: row.description ?? undefined,
    permissions: row.permissions as AccessControl.IRole['permissions'],
    inherits: row.inherits ?? [],
    scope: row.scope ?? undefined,
    metadata: (row.metadata as AccessControl.IRole['metadata']) ?? undefined,
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
