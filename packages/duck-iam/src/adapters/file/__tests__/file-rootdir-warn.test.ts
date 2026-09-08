import { describe, expect, it, vi } from 'vitest'
import type { IamFile } from '../index'

/**
 * The missing-`rootDir` warning is latched in a module-level
 * `_ROOTDIR_WARNED_FIRED`, and `file.test.ts` trips it at collection time: the
 * `runAdapterCompliance(...)` call at the top of that file constructs adapters
 * with no `rootDir` before any `it` runs.
 *
 * So the two clauses there could not fail. "At most one warning" was asserted
 * against a run where zero fire, and "the warning does not echo the path" was a
 * `for` loop over an empty array - a test that passes by iterating nothing.
 * Both were honest about the latch in their comments and neither could detect
 * the thing it named.
 *
 * Isolating the module is the whole fix: `vi.resetModules()` plus a dynamic
 * import gives a fresh `_ROOTDIR_WARNED_FIRED`, so the first construction in
 * each test really is the first one that module has seen.
 */
async function freshAdapterModule() {
  vi.resetModules()
  return await import('../index')
}

function fakeFs(): IamFile.IFS {
  return {
    async mkdir() {},
    async readFile(): Promise<string> {
      const err = new Error('ENOENT') as NodeJS.ErrnoException
      err.code = 'ENOENT'
      throw err
    },
    async writeFile() {},
  }
}

/** Only the warns about `rootDir` - the module may warn about other things. */
function rootDirWarns(spy: { mock: { calls: unknown[][] } }): string[] {
  return spy.mock.calls.map((c) => String(c[0])).filter((m) => /rootDir/.test(m))
}

describe('the missing-rootDir warning, against a module whose latch has not fired', () => {
  it('fires once for a construction with no rootDir', async () => {
    const { IamFileAdapter } = await freshAdapterModule()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      new IamFileAdapter({ fs: fakeFs(), path: '/store-1.json' })
      expect(rootDirWarns(warn)).toHaveLength(1)
    } finally {
      warn.mockRestore()
    }
  })

  it('fires exactly once across many constructions, not once each', async () => {
    // The latch's actual contract. Under the old test this read
    // `0 <= 1` and would have passed with the latch removed entirely.
    const { IamFileAdapter } = await freshAdapterModule()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      new IamFileAdapter({ fs: fakeFs(), path: '/store-1.json' })
      new IamFileAdapter({ fs: fakeFs(), path: '/store-2.json' })
      new IamFileAdapter({ fs: fakeFs(), path: '/store-3.json' })
      expect(rootDirWarns(warn)).toHaveLength(1)
    } finally {
      warn.mockRestore()
    }
  })

  it('does not echo the constructed path', async () => {
    // The path can be request-derived, and this line goes to operator logs; a
    // warning that names it turns the log into a path-existence oracle.
    const { IamFileAdapter } = await freshAdapterModule()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const uniquePath = `/very-unique-path-${Date.now()}.json`
    try {
      new IamFileAdapter({ fs: fakeFs(), path: uniquePath })
      const warns = rootDirWarns(warn)
      // Not an empty loop: the warning is required to have fired.
      expect(warns).toHaveLength(1)
      expect(warns[0]).not.toContain(uniquePath)
      expect(warns[0]).not.toContain('very-unique-path')
    } finally {
      warn.mockRestore()
    }
  })

  it('does not warn at all when rootDir is supplied', async () => {
    const { IamFileAdapter } = await freshAdapterModule()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      new IamFileAdapter({ fs: fakeFs(), path: '/srv/iam/store.json', rootDir: '/srv/iam' })
      expect(rootDirWarns(warn)).toEqual([])
    } finally {
      warn.mockRestore()
    }
  })

  it('a rootDir-less construction after a rootDir one still warns once', async () => {
    // The latch is about repetition, not about "the first adapter ever built".
    const { IamFileAdapter } = await freshAdapterModule()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      new IamFileAdapter({ fs: fakeFs(), path: '/srv/iam/store.json', rootDir: '/srv/iam' })
      new IamFileAdapter({ fs: fakeFs(), path: '/store-1.json' })
      new IamFileAdapter({ fs: fakeFs(), path: '/store-2.json' })
      expect(rootDirWarns(warn)).toHaveLength(1)
    } finally {
      warn.mockRestore()
    }
  })
})
