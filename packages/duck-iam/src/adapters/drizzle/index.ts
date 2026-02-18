import type { Adapter, Attributes, Policy, Role, ScopedRole } from '../../core/types'

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

interface RoleRow {
  id: string
  name: string
  description: string | null
  permissions: string | unknown
  inherits: string | unknown | null
  scope: string | null
  metadata: string | unknown | null
}

interface AssignmentRow {
  subjectId: string
  roleId: string
  scope: string | null
}

interface AttrRow {
  subjectId: string
  data: string | unknown
}

export interface DrizzleConfig {
  db: {
    select: () => { from: (table: unknown) => DrizzleQuery }
    insert: (table: unknown) => { values: (data: Record<string, unknown>) => DrizzleInsert }
    delete: (table: unknown) => { where: (condition: unknown) => Promise<unknown> }
  }
  tables: {
    policies: DrizzleTable
    roles: DrizzleTable
    assignments: DrizzleTable
    attrs: DrizzleTable
  }
  ops: {
    eq: (col: unknown, val: unknown) => unknown
    and: (...conditions: unknown[]) => unknown
  }
}

interface DrizzleTable {
  id?: unknown
  subjectId?: unknown
  roleId?: unknown
  scope?: unknown
  [key: string]: unknown
}

interface DrizzleQuery {
  where: (condition: unknown) => { limit: (n: number) => Promise<Record<string, unknown>[]> }
  limit: (n: number) => Promise<Record<string, unknown>[]>
  then: (onfulfilled: (value: Record<string, unknown>[]) => unknown) => Promise<unknown>
  [Symbol.iterator]?: unknown
}

interface DrizzleInsert {
  onConflictDoUpdate: (args: { target: unknown; set: Record<string, unknown> }) => Promise<unknown>
  onConflictDoNothing: () => Promise<unknown>
}

export class DrizzleAdapter<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
> implements Adapter<TAction, TResource, TRole, TScope>
{
  private db: DrizzleConfig['db']
  private t: DrizzleConfig['tables']
  private eq: DrizzleConfig['ops']['eq']
  private and: DrizzleConfig['ops']['and']

  constructor(config: DrizzleConfig) {
    this.db = config.db
    this.t = config.tables
    this.eq = config.ops.eq
    this.and = config.ops.and
  }

  // -- PolicyStore --

  async listPolicies(): Promise<Policy<TAction, TResource, TRole>[]> {
    const rows = (await this.db.select().from(this.t.policies)) as unknown as PolicyRow[]
    return rows.map(parsePolicy) as Policy<TAction, TResource, TRole>[]
  }

  async getPolicy(id: string): Promise<Policy<TAction, TResource, TRole> | null> {
    const rows = (await this.db
      .select()
      .from(this.t.policies)
      .where(this.eq(this.t.policies.id, id))
      .limit(1)) as unknown as PolicyRow[]
    return rows[0] ? (parsePolicy(rows[0]) as Policy<TAction, TResource, TRole>) : null
  }

  async savePolicy(p: Policy<TAction, TResource, TRole>): Promise<void> {
    const data = serializePolicy(p)
    await this.db.insert(this.t.policies).values(data).onConflictDoUpdate({ target: this.t.policies.id, set: data })
  }

  async deletePolicy(id: string): Promise<void> {
    await this.db.delete(this.t.policies).where(this.eq(this.t.policies.id, id))
  }

  // -- RoleStore --

  async listRoles(): Promise<Role<TAction, TResource, TRole, TScope>[]> {
    const rows = (await this.db.select().from(this.t.roles)) as unknown as RoleRow[]
    return rows.map(parseRole) as Role<TAction, TResource, TRole, TScope>[]
  }

  async getRole(id: string): Promise<Role<TAction, TResource, TRole, TScope> | null> {
    const rows = (await this.db
      .select()
      .from(this.t.roles)
      .where(this.eq(this.t.roles.id, id))
      .limit(1)) as unknown as RoleRow[]
    return rows[0] ? (parseRole(rows[0]) as Role<TAction, TResource, TRole, TScope>) : null
  }

  async saveRole(r: Role<TAction, TResource, TRole, TScope>): Promise<void> {
    const data = serializeRole(r)
    await this.db.insert(this.t.roles).values(data).onConflictDoUpdate({ target: this.t.roles.id, set: data })
  }

  async deleteRole(id: string): Promise<void> {
    await this.db.delete(this.t.roles).where(this.eq(this.t.roles.id, id))
  }

  // -- SubjectStore --

  async getSubjectRoles(subjectId: string): Promise<TRole[]> {
    const rows = (await this.db
      .select()
      .from(this.t.assignments)
      .where(this.eq(this.t.assignments.subjectId, subjectId))) as unknown as AssignmentRow[]
    return [...new Set(rows.map((r) => r.roleId as TRole))]
  }

  async getSubjectScopedRoles(subjectId: string): Promise<ScopedRole<TRole, TScope>[]> {
    const rows = (await this.db
      .select()
      .from(this.t.assignments)
      .where(this.eq(this.t.assignments.subjectId, subjectId))) as unknown as AssignmentRow[]
    return rows.filter((r) => r.scope != null).map((r) => ({ role: r.roleId as TRole, scope: r.scope as TScope }))
  }

  async assignRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void> {
    await this.db
      .insert(this.t.assignments)
      .values({ subjectId, roleId, scope: scope ?? null })
      .onConflictDoNothing()
  }

  async revokeRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void> {
    const conditions = [this.eq(this.t.assignments.subjectId, subjectId), this.eq(this.t.assignments.roleId, roleId)]
    if (scope) conditions.push(this.eq(this.t.assignments.scope, scope))
    await this.db.delete(this.t.assignments).where(this.and(...conditions))
  }

  async getSubjectAttributes(subjectId: string): Promise<Attributes> {
    const rows = (await this.db
      .select()
      .from(this.t.attrs)
      .where(this.eq(this.t.attrs.subjectId, subjectId))
      .limit(1)) as unknown as AttrRow[]
    if (!rows[0]) return {}
    const data = rows[0].data
    return typeof data === 'string' ? JSON.parse(data) : ((data as Attributes) ?? {})
  }

  async setSubjectAttributes(subjectId: string, attrs: Attributes): Promise<void> {
    const existing = await this.getSubjectAttributes(subjectId)
    const merged = JSON.stringify({ ...existing, ...attrs })
    await this.db
      .insert(this.t.attrs)
      .values({ subjectId, data: merged })
      .onConflictDoUpdate({ target: this.t.attrs.subjectId, set: { data: merged } })
  }
}

// -- Serialization helpers --

function parsePolicy(row: PolicyRow): Policy {
  return {
    id: row.id,
    name: row.name,
    description: row.description ?? undefined,
    version: row.version,
    algorithm: row.algorithm as Policy['algorithm'],
    rules: typeof row.rules === 'string' ? JSON.parse(row.rules) : (row.rules as Policy['rules']),
    targets: row.targets
      ? typeof row.targets === 'string'
        ? JSON.parse(row.targets)
        : (row.targets as Policy['targets'])
      : undefined,
  }
}

function serializePolicy(p: Policy): Record<string, unknown> {
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

function parseRole(row: RoleRow): Role {
  return {
    id: row.id,
    name: row.name,
    description: row.description ?? undefined,
    permissions:
      typeof row.permissions === 'string' ? JSON.parse(row.permissions) : (row.permissions as Role['permissions']),
    inherits: typeof row.inherits === 'string' ? JSON.parse(row.inherits) : ((row.inherits as string[]) ?? []),
    scope: row.scope ?? undefined,
    metadata: row.metadata
      ? typeof row.metadata === 'string'
        ? JSON.parse(row.metadata)
        : (row.metadata as Role['metadata'])
      : undefined,
  }
}

function serializeRole(r: Role): Record<string, unknown> {
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
