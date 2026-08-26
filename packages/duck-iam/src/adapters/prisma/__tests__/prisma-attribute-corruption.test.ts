import { describe, expect, it, vi } from 'vitest'
import { IamPrismaAdapter } from '../index'

function makePrismaWithAttrs(data: unknown): {
  adapter: IamPrismaAdapter
  attrs: Map<string, { subjectId: string; data: unknown }>
} {
  const attrs = new Map<string, { subjectId: string; data: unknown }>()
  if (data !== undefined) attrs.set('user-1', { subjectId: 'user-1', data })
  const prisma = {
    accessPolicy: {
      findMany: vi.fn(),
      findUnique: vi.fn(),
      upsert: vi.fn(),
      delete: vi.fn(),
    },
    accessRole: {
      findMany: vi.fn(),
      findUnique: vi.fn(),
      upsert: vi.fn(),
      delete: vi.fn(),
    },
    accessAssignment: {
      findMany: vi.fn(),
      create: vi.fn(),
      deleteMany: vi.fn(),
      updateMany: vi.fn(),
    },
    accessSubjectAttr: {
      findUnique: vi.fn(async ({ where }: { where: { subjectId: string } }) => attrs.get(where.subjectId) ?? null),
      upsert: vi.fn(
        async ({
          where,
          create,
          update,
        }: {
          where: { subjectId: string }
          create: Record<string, unknown>
          update: Record<string, unknown>
        }) => {
          const ex = attrs.get(where.subjectId)
          if (ex) attrs.set(where.subjectId, { subjectId: where.subjectId, data: update.data })
          else attrs.set(where.subjectId, { subjectId: where.subjectId, data: create.data })
          return attrs.get(where.subjectId)!
        },
      ),
    },
  }
  const adapter = new IamPrismaAdapter(prisma)
  return { adapter, attrs }
}

describe('IamPrismaAdapter attribute corruption defense', () => {
  it('returns {} when no row exists (control)', async () => {
    const { adapter } = makePrismaWithAttrs(undefined)
    expect(await adapter.getSubjectAttributes('user-1')).toEqual({})
  })

  it('returns the attributes when row.data is a well-formed object', async () => {
    const { adapter } = makePrismaWithAttrs({ tier: 'pro', verified: true })
    expect(await adapter.getSubjectAttributes('user-1')).toEqual({ tier: 'pro', verified: true })
  })

  it('throws when row.data is a string (corruption)', async () => {
    const { adapter } = makePrismaWithAttrs('admin')
    await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow(/corrupted attributes/)
  })

  it('throws when row.data is null (treated as corruption)', async () => {
    const { adapter } = makePrismaWithAttrs(null)
    await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow(/corrupted attributes/)
  })

  it('throws when row.data is an array (NOT a JSON object)', async () => {
    const { adapter } = makePrismaWithAttrs([1, 2, 3])
    await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow(/corrupted attributes/)
  })

  it('throws when row.data is a number', async () => {
    const { adapter } = makePrismaWithAttrs(42)
    await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow(/corrupted attributes/)
  })

  it('throws when row.data is a boolean', async () => {
    const { adapter } = makePrismaWithAttrs(true)
    await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow(/corrupted attributes/)
  })

  it('returns a FRESH bag (mutations on caller side do not affect Prisma-managed row)', async () => {
    const { adapter, attrs } = makePrismaWithAttrs({ tier: 'pro' })
    const a = await adapter.getSubjectAttributes('user-1')
    a.tier = 'free'
    const stored = attrs.get('user-1')!.data as { tier: string }
    expect(stored.tier).toBe('pro')
  })

  describe('setSubjectAttributes recovery (admin lockout defense)', () => {
    it('overwrites corrupt existing data without throwing, admin can recover', async () => {
      const { adapter, attrs } = makePrismaWithAttrs('corrupt-string')
      await adapter.setSubjectAttributes('user-1', { tier: 'pro' })
      const stored = attrs.get('user-1')!.data as { tier: string }
      expect(stored.tier).toBe('pro')
    })

    it('merges into well-formed existing data normally', async () => {
      const { adapter, attrs } = makePrismaWithAttrs({ tier: 'pro' })
      await adapter.setSubjectAttributes('user-1', { verified: true })
      const stored = attrs.get('user-1')!.data as Record<string, unknown>
      expect(stored).toEqual({ tier: 'pro', verified: true })
    })
  })
})
