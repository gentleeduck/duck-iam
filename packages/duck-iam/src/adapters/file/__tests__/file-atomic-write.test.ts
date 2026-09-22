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
  // NOTE: file bytes cannot show this, since `_flushNow` serialises the live `_cache` and concurrent payloads match.
  // These tests observe that each write/rename pair completes before the next begins.
  it('one flush completes its write and rename before the next begins', async () => {
    const { files, fs } = fakeFs(true)
    const log: string[] = []
    const traced: IamFile.IFS = {
      ...fs,
      async rename(oldPath: string, newPath: string) {
        // Hold the first rename open so an unserialised second flush would start writing inside it.
        if (log.filter((e) => e === 'rename').length === 0) await new Promise((r) => setTimeout(r, 20))
        await fs.rename?.(oldPath, newPath)
        log.push('rename')
      },
      async writeFile(path: string, data: string) {
        log.push('write')
        await fs.writeFile(path, data, 'utf8')
      },
    }
    const adapter = new IamFileAdapter({ fs: traced, path: PATH, rootDir: ROOT })

    await Promise.all([adapter.savePolicy({ ...policy, id: 'first' }), adapter.savePolicy({ ...policy, id: 'second' })])

    // Interleaved would be write, write, rename, rename.
    expect(log).toEqual(['write', 'rename', 'write', 'rename'])
    const onDisk = JSON.parse(files.get(PATH) ?? '{}')
    expect(Object.keys(onDisk.policies).sort()).toEqual(['first', 'second'])
  })

  it('never leaves two temp files unresolved at once', async () => {
    const { files, fs } = fakeFs(true)
    let peakTmp = 0
    const traced: IamFile.IFS = {
      ...fs,
      async rename(oldPath: string, newPath: string) {
        await new Promise((r) => setTimeout(r, 5))
        await fs.rename?.(oldPath, newPath)
      },
      async writeFile(path: string, data: string) {
        await fs.writeFile(path, data, 'utf8')
        const tmp = [...files.keys()].filter((k) => k.endsWith('.tmp')).length
        if (tmp > peakTmp) peakTmp = tmp
      },
    }
    const adapter = new IamFileAdapter({ fs: traced, path: PATH, rootDir: ROOT })

    await Promise.all([
      adapter.savePolicy({ ...policy, id: 'a' }),
      adapter.savePolicy({ ...policy, id: 'b' }),
      adapter.savePolicy({ ...policy, id: 'c' }),
    ])

    expect(peakTmp).toBe(1)
    expect([...files.keys()]).toEqual([PATH])
  })

  /** A driver whose first `rename` fails and whose later ones work. */
  function flakyOnce(fs: IamFile.IFS): IamFile.IFS {
    let calls = 0
    return {
      ...fs,
      async rename(oldPath: string, newPath: string) {
        calls++
        if (calls === 1) throw new Error('transient')
        await fs.rename?.(oldPath, newPath)
      },
    }
  }

  // Both writes share one cache object, so the queued flush must not carry the failed write's mutation to disk.
  it('a write queued behind a failed one is refused rather than handed the failed state', async () => {
    const { files, fs } = fakeFs(true)
    const adapter = new IamFileAdapter({ fs: flakyOnce(fs), path: PATH, rootDir: ROOT })
    // Issued together, so the second flush is queued on the chain behind the failing one.
    const [doomed, queued] = await Promise.allSettled([
      adapter.savePolicy({ ...policy, id: 'doomed' }),
      adapter.savePolicy({ ...policy, id: 'queued' }),
    ])
    expect(doomed.status).toBe('rejected')
    expect(doomed.status === 'rejected' && String(doomed.reason)).toContain('transient')
    // Its mutation lives in the discarded state, so it must not report success.
    expect(queued.status).toBe('rejected')
    expect(queued.status === 'rejected' && String(queued.reason)).toContain('did not reach the store')
    expect(files.get(PATH)).toBeUndefined()
  })

  it('a write issued after a failure succeeds, and the refused write is not in it', async () => {
    const { files, fs } = fakeFs(true)
    files.set(PATH, JSON.stringify({ assignments: {}, attributes: {}, policies: { old: policy }, roles: {} }))
    const adapter = new IamFileAdapter({ fs: flakyOnce(fs), path: PATH, rootDir: ROOT })

    await expect(adapter.savePolicy({ ...policy, id: 'doomed' })).rejects.toThrow('transient')
    // Sequential, so the cache has been discarded and this call reloads the file.
    await adapter.savePolicy({ ...policy, id: 'later' })

    const onDisk = JSON.parse(files.get(PATH) ?? '{}').policies
    expect(Object.keys(onDisk).sort()).toEqual(['later', 'old'])
    // A refused write must leave no trace in memory either.
    expect(await adapter.getPolicy('doomed')).toBeNull()
    expect((await adapter.getPolicy('later'))?.id).toBe('later')
  })
})
