import type { Adapter, Attributes, Policy, Role } from '../../core/types'

/**
 * Generic Prisma client type so we don't require @prisma/client as a hard dep.
 * Your PrismaClient just needs these models.
 */
interface PrismaLike {
  accessPolicy: {
    findMany: (args?: any) => Promise<any[]>
    findUnique: (args: any) => Promise<any>
    upsert: (args: any) => Promise<any>
    delete: (args: any) => Promise<any>
  }
  accessRole: {
    findMany: (args?: any) => Promise<any[]>
    findUnique: (args: any) => Promise<any>
    upsert: (args: any) => Promise<any>
    delete: (args: any) => Promise<any>
  }
  accessAssignment: {
    findMany: (args: any) => Promise<any[]>
    create: (args: any) => Promise<any>
    deleteMany: (args: any) => Promise<any>
  }
  accessSubjectAttr: {
    findUnique: (args: any) => Promise<any>
    upsert: (args: any) => Promise<any>
  }
}

export class PrismaAdapter implements Adapter {
  constructor(private prisma: PrismaLike) {}

  // ── PolicyStore ──

  async listPolicies(): Promise<Policy[]> {
    const rows = await this.prisma.accessPolicy.findMany()
    return rows.map(toPolicy)
  }

  async getPolicy(id: string): Promise<Policy | null> {
    const row = await this.prisma.accessPolicy.findUnique({ where: { id } })
    return row ? toPolicy(row) : null
  }

  async savePolicy(p: Policy): Promise<void> {
    await this.prisma.accessPolicy.upsert({
      where: { id: p.id },
      create: fromPolicy(p),
      update: fromPolicy(p),
    })
  }

  async deletePolicy(id: string): Promise<void> {
    await this.prisma.accessPolicy.delete({ where: { id } })
  }

  // ── RoleStore ──

  async listRoles(): Promise<Role[]> {
    const rows = await this.prisma.accessRole.findMany()
    return rows.map(toRole)
  }

  async getRole(id: string): Promise<Role | null> {
    const row = await this.prisma.accessRole.findUnique({ where: { id } })
    return row ? toRole(row) : null
  }

  async saveRole(r: Role): Promise<void> {
    await this.prisma.accessRole.upsert({
      where: { id: r.id },
      create: fromRole(r),
      update: fromRole(r),
    })
  }

  async deleteRole(id: string): Promise<void> {
    await this.prisma.accessRole.delete({ where: { id } })
  }

  // ── SubjectStore ──

  async getSubjectRoles(subjectId: string): Promise<string[]> {
    const rows = await this.prisma.accessAssignment.findMany({
      where: { subjectId },
    })
    return rows.map((r: any) => r.roleId)
  }

  async assignRole(subjectId: string, roleId: string, scope?: string): Promise<void> {
    await this.prisma.accessAssignment.create({
      data: { subjectId, roleId, scope: scope ?? null },
    })
  }

  async revokeRole(subjectId: string, roleId: string, scope?: string): Promise<void> {
    await this.prisma.accessAssignment.deleteMany({
      where: { subjectId, roleId, ...(scope ? { scope } : {}) },
    })
  }

  async getSubjectAttributes(subjectId: string): Promise<Attributes> {
    const row = await this.prisma.accessSubjectAttr.findUnique({
      where: { subjectId },
    })
    return (row?.data as Attributes) ?? {}
  }

  async setSubjectAttributes(subjectId: string, attrs: Attributes): Promise<void> {
    const existing = await this.getSubjectAttributes(subjectId)
    const merged = { ...existing, ...attrs }
    await this.prisma.accessSubjectAttr.upsert({
      where: { subjectId },
      create: { subjectId, data: merged as any },
      update: { data: merged as any },
    })
  }
}

// ── Row mappers ──

function toPolicy(row: any): Policy {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    version: row.version,
    algorithm: row.algorithm,
    rules: row.rules as Policy['rules'],
    targets: row.targets as Policy['targets'],
  }
}

function fromPolicy(p: Policy): Record<string, any> {
  return {
    id: p.id,
    name: p.name,
    description: p.description ?? null,
    version: p.version ?? 1,
    algorithm: p.algorithm,
    rules: p.rules as any,
    targets: (p.targets ?? null) as any,
  }
}

function toRole(row: any): Role {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    permissions: row.permissions as Role['permissions'],
    inherits: row.inherits ?? [],
    scope: row.scope,
    metadata: row.metadata as Role['metadata'],
  }
}

function fromRole(r: Role): Record<string, any> {
  return {
    id: r.id,
    name: r.name,
    description: r.description ?? null,
    permissions: r.permissions as any,
    inherits: r.inherits ?? [],
    scope: r.scope ?? null,
    metadata: (r.metadata ?? null) as any,
  }
}
