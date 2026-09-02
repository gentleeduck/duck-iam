import { describe, expect, it } from 'vitest'
import type { IamPrimitives } from '../../../core/types'
import { IamFile, IamFileAdapter } from '../index'

function makeFs(): IamFile.IFS {
  const files = new Map<string, string>([['/store.json', '{}']])
  return {
    async readFile(p: string) {
      const v = files.get(p)
      if (v == null) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      return v
    },
    async writeFile(p: string, d: string) {
      files.set(p, d)
    },
    async mkdir() {},
  }
}

function makeAdapter() {
  return new IamFileAdapter<string, string, string, string>({ path: '/store.json', fs: makeFs(), rootDir: '/' })
}

describe('IamFileAdapter direct-call input shape', () => {
  it('rejects a string attrs value (the spread-to-chars class)', async () => {
    await expect(
      makeAdapter().setSubjectAttributes('user-1', 'admin=true' as unknown as IamPrimitives.Attributes),
    ).rejects.toThrow(/attributes for "user-1" must be a plain object \(got string\)/)
  })

  it('rejects an array attrs value', async () => {
    await expect(
      makeAdapter().setSubjectAttributes('user-1', [1, 2] as unknown as IamPrimitives.Attributes),
    ).rejects.toThrow(/\(got array\)/)
  })

  it('does not corrupt existing attributes on a rejected call', async () => {
    const adapter = makeAdapter()
    await adapter.setSubjectAttributes('user-1', { tier: 'gold' })
    await expect(
      adapter.setSubjectAttributes('user-1', 'attack' as unknown as IamPrimitives.Attributes),
    ).rejects.toThrow()
    expect(await adapter.getSubjectAttributes('user-1')).toEqual({ tier: 'gold' })
  })
})
