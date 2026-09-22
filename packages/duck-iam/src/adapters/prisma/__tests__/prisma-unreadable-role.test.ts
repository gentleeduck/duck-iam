import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { IamPrismaAdapter } from '../index'

describe('prisma names a role row it cannot read', () => {
  // `permissions` is a string, not an array, so `parseRoleRow` refuses it.
  const BAD = { id: 'broken', inherits: [], name: 'Broken', permissions: 'not-an-array' }
  const GOOD = { id: 'ok', inherits: [], name: 'Ok', permissions: [] }

  let warn: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
  })
  afterEach(() => {
    warn.mockRestore()
  })

  function adapter(rows: unknown[]) {
    return new IamPrismaAdapter({
      accessAssignment: { findMany: async () => [] },
      accessPolicy: { findMany: async () => [], findUnique: async () => null },
      accessRole: {
        findMany: async () => rows,
        findUnique: async ({ where }: { where: { id: string } }) =>
          (rows as Array<{ id: string }>).find((r) => r.id === where.id) ?? null,
      },
      accessSubjectAttributes: { findUnique: async () => null },
    } as never)
  }

  it('warns once per unreadable row in listRoles, and still returns the readable ones', async () => {
    expect((await adapter([GOOD, BAD]).listRoles()).map((r) => r.id)).toEqual(['ok'])
    expect(warn).toHaveBeenCalledTimes(1)
  })

  it('warns on getRole too, and still answers null', async () => {
    expect(await adapter([BAD]).getRole('broken')).toBeNull()
    expect(warn).toHaveBeenCalledTimes(1)
  })

  it('names the row and the reason, the way the other adapters do', async () => {
    await adapter([BAD]).getRole('broken')
    const message = String(warn.mock.calls[0]?.[0])
    expect(message).toContain('[@gentleduck/iam:prisma]')
    expect(message).toContain('unreadable role row "broken"')
    // The issues from `validateRole`, not just "it was bad".
    expect(message).toMatch(/permissions/i)
  })

  it('says nothing about a catalog that is entirely readable', async () => {
    expect((await adapter([GOOD]).listRoles()).map((r) => r.id)).toEqual(['ok'])
    expect(await adapter([GOOD]).getRole('ok')).not.toBeNull()
    expect(warn).not.toHaveBeenCalled()
  })

  it('still SKIPS the role rather than throwing - a policy is refused, a role is not', async () => {
    // NOTE: the skip/refuse asymmetry is deliberate; see `_readPolicy`.
    await expect(adapter([BAD]).listRoles()).resolves.toEqual([])
  })

  it('warns for each bad row when several are corrupt', async () => {
    const rows = [BAD, { ...BAD, id: 'broken-2' }, GOOD]
    expect((await adapter(rows).listRoles()).map((r) => r.id)).toEqual(['ok'])
    expect(warn).toHaveBeenCalledTimes(2)
  })
})
