import { describe, expect, it, vi } from 'vitest'
import { IamPrismaAdapter } from '../index'

function makePrismaWithAttrs(data: unknown): {
  adapter: IamPrismaAdapter
  attrs: Map<string, { subjectId: string; data: unknown }>
  /** The next attribute query rejects with `err`, the way a driver does when the connection drops. */
  failNextRead: (err: Error) => void
} {
  const attrs = new Map<string, { subjectId: string; data: unknown }>()
  let nextReadError: Error | undefined
  if (data !== undefined) attrs.set('user-1', { subjectId: 'user-1', data })
  const prisma = {
    accessPolicy: {
      findMany: vi.fn(),
      findUnique: vi.fn(),
      upsert: vi.fn(),
      deleteMany: vi.fn(),
    },
    accessRole: {
      findMany: vi.fn(),
      findUnique: vi.fn(),
      upsert: vi.fn(),
      deleteMany: vi.fn(),
    },
    accessAssignment: {
      findMany: vi.fn(),
      create: vi.fn(),
      deleteMany: vi.fn(),
      updateMany: vi.fn(),
    },
    accessSubjectAttr: {
      findUnique: vi.fn(async ({ where }: { where: { subjectId: string } }) => {
        const err = nextReadError
        nextReadError = undefined
        if (err !== undefined) throw err
        return attrs.get(where.subjectId) ?? null
      }),
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
  return {
    adapter,
    attrs,
    failNextRead: (err) => {
      nextReadError = err
    },
  }
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

    it('warns when it overwrites a corrupt bag', async () => {
      const { adapter } = makePrismaWithAttrs('corrupt-string')
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
      try {
        await adapter.setSubjectAttributes('user-1', { tier: 'pro' })
        expect(warn).toHaveBeenCalledTimes(1)
        expect(String(warn.mock.calls[0]?.[0])).toContain('are corrupt')
      } finally {
        warn.mockRestore()
      }
    })

    it('a read that failed for any other reason refuses the write and leaves the bag untouched', async () => {
      const { adapter, attrs, failNextRead } = makePrismaWithAttrs({ tier: 'pro' })
      failNextRead(new Error('connection terminated'))
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
      try {
        await expect(adapter.setSubjectAttributes('user-1', { verified: true })).rejects.toThrow(
          /connection terminated/,
        )
        expect(attrs.get('user-1')?.data).toEqual({ tier: 'pro' })
        expect(warn).not.toHaveBeenCalled()
      } finally {
        warn.mockRestore()
      }
    })

    it('control: getSubjectAttributes surfaces a failed query as that failure', async () => {
      const { adapter, failNextRead } = makePrismaWithAttrs({ tier: 'pro' })
      failNextRead(new Error('connection terminated'))
      const err = await adapter.getSubjectAttributes('user-1').then(
        () => null,
        (e: unknown) => e,
      )
      expect(err instanceof Error && err.message).toBe('connection terminated')
      expect(await adapter.getSubjectAttributes('user-1')).toEqual({ tier: 'pro' })
    })
  })
})

// A non-object payload must throw like on every adapter, not spread into per-character keys.
describe('IamPrismaAdapter rejects a non-object attribute payload', () => {
  it.each([
    ['a string', '"abc"'],
    ['an array', '[1,2]'],
    ['null', 'null'],
    ['a number', '7'],
  ])('rejects %s without writing', async (_label, json) => {
    const { adapter, attrs } = makePrismaWithAttrs(undefined)
    await expect(adapter.setSubjectAttributes('user-1', JSON.parse(json))).rejects.toThrow('IAM_ATTRIBUTES_INVALID')
    expect(attrs.size).toBe(0)
  })

  // Control: an ordinary object still writes, so the rejections above are not
  // the method having become inert.
  it('control: writes a plain object', async () => {
    const { adapter, attrs } = makePrismaWithAttrs(undefined)
    await adapter.setSubjectAttributes('user-1', { tier: 'gold' })
    expect(attrs.get('user-1')?.data).toEqual({ tier: 'gold' })
  })
})
