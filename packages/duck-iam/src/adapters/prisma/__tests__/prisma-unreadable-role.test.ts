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

  it('warns once per unreadable row in listRoles, and refuses the read', async () => {
    await expect(adapter([GOOD, BAD]).listRoles()).rejects.toThrow('IAM_UNREADABLE_ROLE')
    expect(warn).toHaveBeenCalledTimes(1)
  })

  it('warns on getRole too, and refuses rather than answering null', async () => {
    await expect(adapter([BAD]).getRole('broken')).rejects.toThrow('IAM_UNREADABLE_ROLE')
    expect(warn).toHaveBeenCalledTimes(1)
  })

  it('names the row and the reason, the way the other adapters do', async () => {
    await adapter([BAD])
      .getRole('broken')
      .catch(() => {})
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

  it('refuses the read rather than returning the readable half', async () => {
    // Not `['ok']`: a deny selects on the role id, so the half that went missing may be the half that denied.
    await expect(adapter([BAD, GOOD]).listRoles()).rejects.toThrow('IAM_UNREADABLE_ROLE')
  })

  it('warns for the first bad row, then stops at it', async () => {
    const rows = [BAD, { ...BAD, id: 'broken-2' }, GOOD]
    await expect(adapter(rows).listRoles()).rejects.toThrow('IAM_UNREADABLE_ROLE')
    expect(warn).toHaveBeenCalledTimes(1)
  })
})
