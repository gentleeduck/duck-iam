import { describe, expect, it } from 'vitest'
import { type IamFile, IamFileAdapter } from '../index'

const ROOT = '/store'
const PATH = '/store/iam.json'

function fakeFs(withRename: boolean) {
  const files = new Map<string, string>()
  const writes: string[] = []
  const fs: IamFile.IFS = {
    async mkdir() {
      return undefined
    },
    async readFile(path) {
      const v = files.get(path)
      if (v === undefined) {
        throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      }
      return v
    },
    async writeFile(path, data) {
      writes.push(path)
      files.set(path, data)
    },
    ...(withRename && {
      async rename(oldPath: string, newPath: string) {
        const v = files.get(oldPath)
        if (v === undefined) throw new Error('ENOENT')
        files.delete(oldPath)
        files.set(newPath, v)
      },
    }),
  }
  return { files, fs, writes }
}

const policy = { algorithm: 'deny-overrides' as const, id: 'p1', name: 'p1', rules: [] }

describe('file adapter writes atomically when the driver supports rename', () => {
  it('writes to a temp path and renames it over the store', async () => {
    const { files, fs, writes } = fakeFs(true)
    const adapter = new IamFileAdapter({ fs, path: PATH, rootDir: ROOT })
    await adapter.savePolicy(policy)

    expect(writes).toHaveLength(1)
    expect(writes[0]).not.toBe(PATH)
    expect(writes[0]).toMatch(/^\/store\/iam\.json\..*\.tmp$/)
    expect([...files.keys()]).toEqual([PATH])
    expect(JSON.parse(files.get(PATH) ?? '{}').policies.p1.id).toBe('p1')
  })

  it('leaves the previous contents intact when the rename never happens', async () => {
    const { files, fs } = fakeFs(true)
    files.set(PATH, JSON.stringify({ policies: { old: policy }, roles: {} }))
    const failing: IamFile.IFS = {
      ...fs,
      async rename() {
        throw new Error('crash before rename')
      },
    }
    const adapter = new IamFileAdapter({ fs: failing, path: PATH, rootDir: ROOT })
    await expect(adapter.savePolicy(policy)).rejects.toThrow('crash before rename')
    expect(JSON.parse(files.get(PATH) ?? '{}').policies.old.id).toBe('p1')
  })

  it('falls back to an in-place write when the driver has no rename', async () => {
    const { files, fs, writes } = fakeFs(false)
    const adapter = new IamFileAdapter({ fs, path: PATH, rootDir: ROOT })
    await adapter.savePolicy(policy)
    expect(writes).toEqual([PATH])
    expect([...files.keys()]).toEqual([PATH])
  })
})

describe('concurrent flushes are serialised', () => {
  it('the last write to be issued is the one left on disk', async () => {
    const { files, fs } = fakeFs(true)
    let renames = 0
    const slowFirstRename: IamFile.IFS = {
      ...fs,
      async rename(oldPath: string, newPath: string) {
        renames++
        // Make the first rename land after the second would have, so an
        // unserialised implementation leaves the older snapshot on disk.
        if (renames === 1) await new Promise((r) => setTimeout(r, 20))
        await fs.rename?.(oldPath, newPath)
      },
    }
    const adapter = new IamFileAdapter({ fs: slowFirstRename, path: PATH, rootDir: ROOT })

    await Promise.all([adapter.savePolicy({ ...policy, id: 'first' }), adapter.savePolicy({ ...policy, id: 'second' })])

    const onDisk = JSON.parse(files.get(PATH) ?? '{}')
    expect(Object.keys(onDisk.policies).sort()).toEqual(['first', 'second'])
    expect(renames).toBe(2)
  })

  it('a failed write does not poison later writes', async () => {
    const { files, fs } = fakeFs(true)
    let calls = 0
    const flaky: IamFile.IFS = {
      ...fs,
      async rename(oldPath: string, newPath: string) {
        calls++
        if (calls === 1) throw new Error('transient')
        await fs.rename?.(oldPath, newPath)
      },
    }
    const adapter = new IamFileAdapter({ fs: flaky, path: PATH, rootDir: ROOT })
    await expect(adapter.savePolicy({ ...policy, id: 'doomed' })).rejects.toThrow('transient')
    await adapter.savePolicy({ ...policy, id: 'ok' })
    expect(JSON.parse(files.get(PATH) ?? '{}').policies.ok.id).toBe('ok')
  })
})
