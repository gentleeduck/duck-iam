import type { Adapter, Policy, Role, Attributes } from '../../core/types'

/**
 * Drizzle adapter.
 * Works with PostgreSQL, MySQL, SQLite, Cloudflare D1, Turso, LibSQL.
 *
 * You provide:
 *   1. Your drizzle `db` instance
 *   2. Your drizzle table objects
 *   3. The `eq` and `and` operators from drizzle-orm
 *
 * Example:
 *   import { db } from "./db";
 *   import { eq, and } from "drizzle-orm";
 *   import { accessPolicies, accessRoles, accessAssignments, accessSubjectAttrs } from "./schema";
 *
 *   const adapter = new DrizzleAdapter({
 *     db,
 *     tables: { policies: accessPolicies, roles: accessRoles, assignments: accessAssignments, attrs: accessSubjectAttrs },
 *     ops: { eq, and },
 *   });
 */

export interface DrizzleConfig {
  db: any
  tables: {
    policies: any
    roles: any
    assignments: any
    attrs: any
  }
  ops: {
    eq: (col: any, val: any) => any
    and: (...conditions: any[]) => any
  }
}

export class DrizzleAdapter implements Adapter {
  private db: any
  private t: DrizzleConfig['tables']
  private eq: DrizzleConfig['ops']['eq']
  private and: DrizzleConfig['ops']['and']

  constructor(config: DrizzleConfig) {
    this.db = config.db
    this.t = config.tables
    this.eq = config.ops.eq
    this.and = config.ops.and
  }

  // ── PolicyStore ──

  async listPolicies(): Promise<Policy[]> {
    const rows = await this.db.select().from(this.t.policies)
    return rows.map(parsePolicy)
  }

  async getPolicy(id: string): Promise<Policy | null> {
    const rows = await this.db.select().from(this.t.policies).where(this.eq(this.t.policies.id, id)).limit(1)
    return rows[0] ? parsePolicy(rows[0]) : null
  }

  async savePolicy(p: Policy): Promise<void> {
    const data = serializePolicy(p)
    await this.db.insert(this.t.policies).values(data).onConflictDoUpdate({ target: this.t.policies.id, set: data })
  }

  async deletePolicy(id: string): Promise<void> {
    await this.db.delete(this.t.policies).where(this.eq(this.t.policies.id, id))
  }

  // ── RoleStore ──

  async listRoles(): Promise<Role[]> {
    const rows = await this.db.select().from(this.t.roles)
    return rows.map(parseRole)
  }

  async getRole(id: string): Promise<Role | null> {
    const rows = await this.db.select().from(this.t.roles).where(this.eq(this.t.roles.id, id)).limit(1)
    return rows[0] ? parseRole(rows[0]) : null
  }

  async saveRole(r: Role): Promise<void> {
    const data = serializeRole(r)
    await this.db.insert(this.t.roles).values(data).onConflictDoUpdate({ target: this.t.roles.id, set: data })
  }

  async deleteRole(id: string): Promise<void> {
    await this.db.delete(this.t.roles).where(this.eq(this.t.roles.id, id))
  }

  // ── SubjectStore ──

  async getSubjectRoles(subjectId: string): Promise<string[]> {
    const rows = await this.db.select().from(this.t.assignments).where(this.eq(this.t.assignments.subjectId, subjectId))
    return rows.map((r: any) => r.roleId)
  }

  async assignRole(subjectId: string, roleId: string, scope?: string): Promise<void> {
    await this.db
      .insert(this.t.assignments)
      .values({ subjectId, roleId, scope: scope ?? null })
      .onConflictDoNothing()
  }

  async revokeRole(subjectId: string, roleId: string, scope?: string): Promise<void> {
    const conditions = [this.eq(this.t.assignments.subjectId, subjectId), this.eq(this.t.assignments.roleId, roleId)]
    if (scope) conditions.push(this.eq(this.t.assignments.scope, scope))
    await this.db.delete(this.t.assignments).where(this.and(...conditions))
  }

  async getSubjectAttributes(subjectId: string): Promise<Attributes> {
    const rows = await this.db.select().from(this.t.attrs).where(this.eq(this.t.attrs.subjectId, subjectId)).limit(1)
    if (!rows[0]) return {}
    const data = rows[0].data
    return typeof data === 'string' ? JSON.parse(data) : (data ?? {})
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

// ── Serialization helpers ──

function parsePolicy(row: any): Policy {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    version: row.version,
    algorithm: row.algorithm,
    rules: typeof row.rules === 'string' ? JSON.parse(row.rules) : row.rules,
    targets: row.targets ? (typeof row.targets === 'string' ? JSON.parse(row.targets) : row.targets) : undefined,
  }
}

function serializePolicy(p: Policy): Record<string, any> {
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

function parseRole(row: any): Role {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    permissions: typeof row.permissions === 'string' ? JSON.parse(row.permissions) : row.permissions,
    inherits: typeof row.inherits === 'string' ? JSON.parse(row.inherits) : (row.inherits ?? []),
    scope: row.scope,
    metadata: row.metadata ? (typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata) : undefined,
  }
}

function serializeRole(r: Role): Record<string, any> {
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
