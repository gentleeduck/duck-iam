import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { type IamFile, IamFileAdapter } from '../index'

/**
 * `_assertWithinRoot` is documented as running on the read and write paths.
 * It ran on *every* write and on reads that reach the filesystem - not on a
 * read served from `_cache`, which returns one line earlier
 * (`file/index.ts:312`). The class comment used to claim "every I/O", which is
 * exactly the claim that makes a reviewer stop looking.
 *
 * These pin the real window: a symlink swapped in after the first read is not
 * re-detected by later reads, and is caught by the next write, which throws
 * rather than following it.
 */

type Fs = IamFile.IFS & { realpaths: Map<string, string>; calls: string[] }

function makeFs(initial: Record<string, unknown>): Fs {
  const files = new Map<string, string>([['/root/store.json', JSON.stringify(initial)]])
  const realpaths = new Map<string, string>([
    ['/root', '/root'],
    ['/root/store.json', '/root/store.json'],
  ])
  const calls: string[] = []
  return {
    calls,
    async mkdir() {},
    async readFile(path: string) {
      const v = files.get(path)
      if (v === undefined) {
        const err: NodeJS.ErrnoException = new Error('ENOENT')
        err.code = 'ENOENT'
        throw err
      }
      return v
    },
    async realpath(path: string) {
      calls.push(path)
      const v = realpaths.get(path)
      if (v === undefined) {
        const err: NodeJS.ErrnoException = new Error('ENOENT')
        err.code = 'ENOENT'
        throw err
      }
      return v
    },
    realpaths,
    async writeFile(path: string, data: string) {
      files.set(path, data)
    },
  }
}

let warn: ReturnType<typeof vi.spyOn> | undefined
beforeEach(() => {
  warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  warn?.mockRestore()
})

describe('file adapter containment is checked on a cache miss and on every write', () => {
  it('does not re-run realpath for a read served from cache', async () => {
    const fs = makeFs({ policies: {}, roles: {} })
    const adapter = new IamFileAdapter({ fs, path: '/root/store.json', rootDir: '/root' })
    await adapter.listPolicies()
    const afterFirst = fs.calls.length
    expect(afterFirst).toBeGreaterThan(0)
    await adapter.listPolicies()
    await adapter.listRoles()
    // The documented-but-untrue claim was that every I/O re-checks. It does not.
    expect(fs.calls.length).toBe(afterFirst)
  })

  it('catches a store swapped out from under it at the next write, and fails closed', async () => {
    const fs = makeFs({ policies: {}, roles: {} })
    const adapter = new IamFileAdapter({ fs, path: '/root/store.json', rootDir: '/root' })
    await adapter.listPolicies()

    // The attacker's swap: the store path now resolves outside the root.
    fs.realpaths.set('/root/store.json', '/elsewhere/store.json')

    // A cached read is unaffected - this is the window the comment hid.
    await expect(adapter.listPolicies()).resolves.toEqual([])

    // The write path checks unconditionally and refuses to follow the link.
    await expect(adapter.savePolicy({ algorithm: 'deny-overrides', id: 'p1', name: 'P', rules: [] })).rejects.toThrow(
      /escapes rootDir/,
    )
  })

  // Control: without the swap the same write succeeds, so the rejection above
  // is the containment check and not an unrelated failure.
  it('control: the same write succeeds when the path still resolves inside the root', async () => {
    const fs = makeFs({ policies: {}, roles: {} })
    const adapter = new IamFileAdapter({ fs, path: '/root/store.json', rootDir: '/root' })
    await adapter.listPolicies()
    await expect(
      adapter.savePolicy({ algorithm: 'deny-overrides', id: 'p1', name: 'P', rules: [] }),
    ).resolves.toBeUndefined()
  })
})
