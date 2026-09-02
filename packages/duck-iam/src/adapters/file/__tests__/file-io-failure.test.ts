import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { AccessControl } from '../../../core/types'
import { type IamFile, IamFileAdapter } from '../index'

type A = 'read'
type R = 'post'
type Ro = 'viewer' | 'editor'
type S = 'org-1'

const STORE = '/store.json'

function errno(code: string): NodeJS.ErrnoException {
  const err = new Error(code) as NodeJS.ErrnoException
  err.code = code
  return err
}

/** Fake FS whose individual operations can be made to fail with a given errno. */
function makeFS(fail: { write?: string; mkdir?: string; read?: string } = {}): IamFile.IFS {
  const files = new Map<string, string>()
  const dirs = new Set<string>()
  return {
    async mkdir(path: string) {
      if (fail.mkdir) throw errno(fail.mkdir)
      if (dirs.has(path)) throw errno('EEXIST')
      dirs.add(path)
    },
    async readFile(path: string) {
      if (fail.read) throw errno(fail.read)
      const v = files.get(path)
      if (v == null) throw errno('ENOENT')
      return v
    },
    async writeFile(path: string, data: string) {
      if (fail.write) throw errno(fail.write)
      files.set(path, data)
    },
  }
}

const policy: AccessControl.IPolicy<A, R, Ro> = {
  algorithm: 'deny-overrides',
  id: 'p1',
  name: 'Allow Read',
  rules: [{ actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 10, resources: ['post'] }],
}

describe('IamFileAdapter I/O failure handling', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
  })
  afterEach(() => {
    warnSpy.mockRestore()
  })

  it('surfaces a writeFile failure from every mutating method', async () => {
    const adapter = new IamFileAdapter<A, R, Ro, S>({ fs: makeFS({ write: 'EACCES' }), path: STORE })
    await expect(adapter.savePolicy(policy)).rejects.toThrow(/EACCES/)
    await expect(adapter.deletePolicy('p1')).rejects.toThrow(/EACCES/)
    await expect(adapter.saveRole({ id: 'editor', name: 'Editor', permissions: [] })).rejects.toThrow(/EACCES/)
    await expect(adapter.deleteRole('editor')).rejects.toThrow(/EACCES/)
    await expect(adapter.assignRole('user-1', 'editor')).rejects.toThrow(/EACCES/)
    await expect(adapter.setSubjectAttributes('user-1', { team: 'A' })).rejects.toThrow(/EACCES/)
  })

  it('reports a non-EEXIST mkdir failure with the explicit parent-directory message', async () => {
    const adapter = new IamFileAdapter<A, R, Ro, S>({ fs: makeFS({ mkdir: 'EPERM' }), path: '/nested/store.json' })
    await expect(adapter.savePolicy(policy)).rejects.toThrow(/parent directory "\/nested" is not accessible \(EPERM\)/)
  })

  it('an unreadable store fails the read rather than presenting an empty (deny-everything) store', async () => {
    const adapter = new IamFileAdapter<A, R, Ro, S>({ fs: makeFS({ read: 'EACCES' }), path: STORE })
    await expect(adapter.listPolicies()).rejects.toThrow(/load failed \(EACCES\)/)
    await expect(adapter.getSubjectRoles('user-1')).rejects.toThrow(/load failed \(EACCES\)/)
    await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow(/load failed \(EACCES\)/)
  })

  it('a failed load is not cached - a later successful read still works', async () => {
    let failing = true
    const files = new Map<string, string>([[STORE, JSON.stringify({ policies: { p1: policy } })]])
    const fs: IamFile.IFS = {
      async mkdir() {},
      async readFile(path: string) {
        if (failing) throw errno('EIO')
        const v = files.get(path)
        if (v == null) throw errno('ENOENT')
        return v
      },
      async writeFile() {},
    }
    const adapter = new IamFileAdapter<A, R, Ro, S>({ fs, path: STORE })
    await expect(adapter.listPolicies()).rejects.toThrow(/load failed \(EIO\)/)
    failing = false
    expect((await adapter.listPolicies()).map((p) => p.id)).toEqual(['p1'])
  })

  it('concurrent first reads share one readFile (in-flight dedupe)', async () => {
    let reads = 0
    const fs: IamFile.IFS = {
      async mkdir() {},
      async readFile() {
        reads++
        await new Promise((r) => setTimeout(r, 5))
        return JSON.stringify({ policies: { p1: policy } })
      },
      async writeFile() {},
    }
    const adapter = new IamFileAdapter<A, R, Ro, S>({ fs, path: STORE })
    const [a, b] = await Promise.all([adapter.listPolicies(), adapter.listPolicies()])
    expect(a.map((p) => p.id)).toEqual(['p1'])
    expect(b.map((p) => p.id)).toEqual(['p1'])
    expect(reads).toBe(1)
  })
})
