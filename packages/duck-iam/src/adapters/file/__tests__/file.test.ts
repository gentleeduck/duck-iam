import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { AccessControl } from '../../../core/types'
import { runAdapterCompliance } from '../../__compliance__/compliance'
import { runEngineCapabilityCompliance } from '../../__compliance__/engine-capability'
import { OPTIONAL_SUPPORT } from '../../__compliance__/optional-support'
import { IamFile, IamFileAdapter, iamFileAdapter } from '../index'

type Action = 'read' | 'write'
type Resource = 'post'
type Role = 'viewer' | 'editor'
type Scope = 'org-1'

type FakeFS = IamFile.IFS & {
  files: Map<string, string>
  dirs: Set<string>
  realpathMap: Map<string, string>
}

function makeFakeFS(initial?: string, opts: { storePath?: string; preCreatedDirs?: string[] } = {}): FakeFS {
  const files = new Map<string, string>()
  const realpathMap = new Map<string, string>()
  const dirs = new Set<string>(opts.preCreatedDirs ?? [])
  const storePath = opts.storePath ?? '/store.json'
  if (initial) files.set(storePath, initial)
  return {
    files,
    dirs,
    async readFile(path: string) {
      const v = files.get(path)
      if (v == null) {
        const err = new Error('ENOENT') as NodeJS.ErrnoException
        err.code = 'ENOENT'
        throw err
      }
      return v
    },
    async writeFile(path: string, data: string) {
      files.set(path, data)
    },
    async mkdir(path: string) {
      // Match real fs.mkdir (non-recursive) semantics: EEXIST when present.
      if (dirs.has(path)) {
        const err = new Error('EEXIST') as NodeJS.ErrnoException
        err.code = 'EEXIST'
        throw err
      }
      dirs.add(path)
    },
    // `rename` and `realpath` select the shipped temp-then-rename write path and root containment.
    async rename(from: string, to: string) {
      const data = files.get(from)
      if (data == null) {
        const err = new Error('ENOENT') as NodeJS.ErrnoException
        err.code = 'ENOENT'
        throw err
      }
      files.set(to, data)
      files.delete(from)
    },
    async realpath(path: string) {
      const mapped = realpathMap.get(path)
      if (mapped !== undefined) return mapped
      if (files.has(path) || dirs.has(path)) return path
      const err = new Error('ENOENT') as NodeJS.ErrnoException
      err.code = 'ENOENT'
      throw err
    },
    realpathMap,
  }
}

// Silence the construction-time warn emitted when rootDir is omitted.
let _warnSpy: ReturnType<typeof vi.spyOn> | undefined
beforeEach(() => {
  _warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  _warnSpy?.mockRestore()
})

/**
 * The configuration a real deployment runs: an FS with `rename` and `realpath`, plus a `rootDir`.
 * NOTE: without them the adapter takes the in-place fallback and skips containment, which is not what ships.
 */
function shippedFile(): IamFileAdapter {
  return new IamFileAdapter({
    fs: makeFakeFS(undefined, { preCreatedDirs: ['/data'] }),
    path: '/data/store.json',
    rootDir: '/data',
  })
}

// Fresh fake FS per call, so each compliance scenario starts from an empty store.
runAdapterCompliance('IamFileAdapter', shippedFile, {
  supports: OPTIONAL_SUPPORT.IamFileAdapter,
})

runEngineCapabilityCompliance('IamFileAdapter', shippedFile)

const policy: AccessControl.IPolicy<Action, Resource, Role> = {
  id: 'p1',
  name: 'Allow Read',
  algorithm: 'deny-overrides',
  rules: [{ id: 'r1', effect: 'allow', priority: 10, actions: ['read'], resources: ['post'], conditions: { all: [] } }],
}

describe('IamFileAdapter', () => {
  it('starts empty when file missing', async () => {
    const fs = makeFakeFS()
    const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({ path: '/store.json', fs })
    expect(await adapter.listPolicies()).toEqual([])
    expect(await adapter.listRoles()).toEqual([])
  })

  it('savePolicy + listPolicies roundtrips through JSON', async () => {
    const fs = makeFakeFS()
    const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({ path: '/store.json', fs })
    await adapter.savePolicy(policy)
    // `version: 1` comes from the shared write-path normaliser.
    expect(await adapter.listPolicies()).toEqual([{ ...policy, version: 1 }])
    // Verify on-disk JSON
    const disk = JSON.parse(fs.files.get('/store.json')!)
    expect(disk.policies.p1.name).toBe('Allow Read')
  })

  it('mkdir is called with the parent directory before first write', async () => {
    const fs = makeFakeFS()
    const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({ path: '/data/iam/store.json', fs })
    await adapter.savePolicy(policy)
    expect(fs.dirs.has('/data/iam')).toBe(true)
  })

  it('reloads state from existing file', async () => {
    const seeded = JSON.stringify({ policies: { p1: policy }, roles: {}, assignments: {}, attributes: {} })
    const fs = makeFakeFS(seeded)
    const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({ path: '/store.json', fs })
    const out = await adapter.getPolicy('p1')
    expect(out?.name).toBe('Allow Read')
  })

  it('assignRole + getSubjectRoles persists across calls', async () => {
    const fs = makeFakeFS()
    const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({ path: '/store.json', fs })
    await adapter.saveRole({ id: 'viewer', name: 'Viewer', permissions: [] })
    await adapter.assignRole('user-1', 'viewer')
    expect(await adapter.getSubjectRoles('user-1')).toEqual(['viewer'])
  })

  it('scoped assignments are exposed via getSubjectScopedRoles only', async () => {
    const fs = makeFakeFS()
    const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({ path: '/store.json', fs })
    await adapter.saveRole({ id: 'editor', name: 'Editor', permissions: [] })
    await adapter.assignRole('user-1', 'editor', 'org-1')
    expect(await adapter.getSubjectRoles('user-1')).toEqual([])
    expect(await adapter.getSubjectScopedRoles('user-1')).toEqual([{ role: 'editor', scope: 'org-1' }])
  })

  it('setSubjectAttributes merges, does not replace', async () => {
    const fs = makeFakeFS()
    const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({ path: '/store.json', fs })
    await adapter.setSubjectAttributes('user-1', { department: 'eng' })
    await adapter.setSubjectAttributes('user-1', { status: 'active' })
    expect(await adapter.getSubjectAttributes('user-1')).toEqual({ department: 'eng', status: 'active' })
  })

  it('deletePolicy removes the entry on disk', async () => {
    const fs = makeFakeFS()
    const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({ path: '/store.json', fs })
    await adapter.savePolicy(policy)
    await adapter.deletePolicy('p1')
    expect(await adapter.listPolicies()).toEqual([])
    const disk = JSON.parse(fs.files.get('/store.json')!)
    expect(disk.policies).toEqual({})
  })

  it('throws on malformed JSON instead of silently emptying the store', async () => {
    // A cached `{}` would be persisted by the next flush, destroying recoverable data.
    const fs = makeFakeFS('not-json{')
    const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({ path: '/store.json', fs })
    await expect(adapter.listPolicies()).rejects.toThrow(/corrupt.*refusing to load/)
  })

  describe('malformed-row handling (P0)', () => {
    // A corrupt role row is dropped and reported (the grants left naming it are reported too); a policy row throws,
    // since dropping it would strip its denies. See `iamUnreadablePolicy`.
    it('refuses a policy entry that fails validation, rather than keeping the rest', async () => {
      const seeded = JSON.stringify({
        policies: {
          good: policy,
          // Missing required `algorithm` and `rules` fields.
          bad: { id: 'bad', name: 'broken' },
        },
        roles: {},
        assignments: {},
        attributes: {},
      })
      const errors: Array<{ rowId: string }> = []
      const fs = makeFakeFS(seeded)
      const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({
        path: '/store.json',
        fs,
        onPolicyError: (_err, ctx) => errors.push({ rowId: ctx.rowId }),
      })
      await expect(adapter.listPolicies()).rejects.toThrow(/policy "bad" cannot be read and will not be skipped/)
      expect(errors[0]?.rowId).toBe('bad')
    })

    it('drops a role entry that fails validation', async () => {
      const seeded = JSON.stringify({
        policies: {},
        roles: {
          good: { id: 'good', name: 'g', permissions: [] },
          bad: { name: 'no-id', permissions: [] },
        },
        assignments: {},
        attributes: {},
      })
      const errors: Array<{ rowId: string }> = []
      const fs = makeFakeFS(seeded)
      const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({
        path: '/store.json',
        fs,
        onPolicyError: (_err, ctx) => errors.push({ rowId: ctx.rowId }),
      })
      const list = await adapter.listRoles()
      expect(list.map((r) => r.id)).toEqual(['good'])
      expect(errors[0]?.rowId).toBe('bad')
    })

    it('reports a malformed JSON file via onPolicyError + throws', async () => {
      const errors: Array<{ rowId: string }> = []
      const fs = makeFakeFS('not-json{')
      const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({
        path: '/store.json',
        fs,
        onPolicyError: (_err, ctx) => errors.push({ rowId: ctx.rowId }),
      })
      await expect(adapter.listPolicies()).rejects.toThrow(/corrupt/)
      expect(errors[0]?.rowId).toBe('/store.json')
    })
  })

  describe('path-traversal hardening', () => {
    it('rejects a path containing a ".." segment', () => {
      const fs = makeFakeFS()
      expect(
        () =>
          new IamFileAdapter<Action, Resource, Role, Scope>({
            path: '/var/lib/iam/../../etc/passwd',
            fs,
          }),
      ).toThrow(/".." segment/)
    })

    it('rejects a relative path (must be supplied absolute)', () => {
      const fs = makeFakeFS()
      expect(
        () =>
          new IamFileAdapter<Action, Resource, Role, Scope>({
            path: 'store.json',
            fs,
          }),
      ).toThrow(/absolute/)
    })

    it('accepts a happy-path absolute path under rootDir', async () => {
      const fs = makeFakeFS(undefined, { storePath: '/srv/iam/store.json' })
      const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({
        path: '/srv/iam/store.json',
        rootDir: '/srv/iam',
        fs,
      })
      await adapter.savePolicy(policy)
      expect(fs.files.has('/srv/iam/store.json')).toBe(true)
    })

    it('rejects an absolute path that escapes rootDir', () => {
      const fs = makeFakeFS()
      expect(
        () =>
          new IamFileAdapter<Action, Resource, Role, Scope>({
            path: '/etc/passwd',
            rootDir: '/srv/iam',
            fs,
          }),
      ).toThrow(/escapes rootDir/)
    })

    // The missing-`rootDir` warning is tested in `file-rootdir-warn.test.ts`: the compliance call above trips
    // its module-level latch at collection time, so no test here could observe it.

    it('rejects a symlink that resolves outside rootDir (via realpath)', async () => {
      // Fake a symlink from /srv/iam/store.json to /etc/passwd: the textual check passes, but the realpath
      // check on first read must reject.
      const fs: IamFile.IFS = {
        async readFile() {
          throw new Error('should never read - rejected first')
        },
        async writeFile() {
          throw new Error('should never write - rejected first')
        },
        async mkdir() {},
        async realpath(p: string): Promise<string> {
          if (p === '/srv/iam/store.json') return '/etc/passwd'
          if (p === '/srv/iam') return '/srv/iam'
          throw new Error('ENOENT')
        },
      }
      const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({
        path: '/srv/iam/store.json',
        rootDir: '/srv/iam',
        fs,
      })
      await expect(adapter.listPolicies()).rejects.toThrow(/symlink traversal/)
    })

    it('rethrows non-ENOENT realpath errors instead of falling through to parent', async () => {
      // SECURITY: ELOOP must not fall back to the parent realpath, or a hostile symlink bypasses containment.
      const fs: IamFile.IFS = {
        async readFile() {
          return JSON.stringify({ policies: {}, roles: {}, assignments: {}, attributes: {} })
        },
        async writeFile() {},
        async mkdir() {},
        async realpath(p: string): Promise<string> {
          if (p === '/srv/iam/store.json') {
            const err = new Error('ELOOP') as NodeJS.ErrnoException
            err.code = 'ELOOP'
            throw err
          }
          if (p === '/srv/iam') return '/srv/iam'
          throw new Error('ENOENT')
        },
      }
      const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({
        path: '/srv/iam/store.json',
        rootDir: '/srv/iam',
        fs,
      })
      await expect(adapter.listPolicies()).rejects.toThrow(/ELOOP/)
    })

    it('still falls back to parent realpath when file is ENOENT', async () => {
      // A genuinely missing file (first run) still checks containment via parent + basename.
      const fs: IamFile.IFS = {
        async readFile() {
          throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
        },
        async writeFile() {},
        async mkdir() {},
        async realpath(p: string): Promise<string> {
          if (p === '/srv/iam/store.json') {
            const err = new Error('ENOENT') as NodeJS.ErrnoException
            err.code = 'ENOENT'
            throw err
          }
          if (p === '/srv/iam') return '/srv/iam'
          throw new Error('ENOENT')
        },
      }
      const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({
        path: '/srv/iam/store.json',
        rootDir: '/srv/iam',
        fs,
      })
      // Empty result, no throw - containment satisfied via parent fallback.
      expect(await adapter.listPolicies()).toEqual([])
    })

    it('_loadInFlight clears after symlink-escape rejection', async () => {
      // The in-flight slot must clear on any throw so a fixed filesystem can be retried.
      let escapingSymlink = true
      const fs: IamFile.IFS = {
        async readFile() {
          return JSON.stringify({ policies: {}, roles: {}, assignments: {}, attributes: {} })
        },
        async writeFile() {},
        async mkdir() {},
        async realpath(p: string): Promise<string> {
          if (p === '/srv/iam/store.json') return escapingSymlink ? '/etc/passwd' : '/srv/iam/store.json'
          if (p === '/srv/iam') return '/srv/iam'
          throw new Error('ENOENT')
        },
      }
      const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({
        path: '/srv/iam/store.json',
        rootDir: '/srv/iam',
        fs,
      })
      await expect(adapter.listPolicies()).rejects.toThrow(/symlink traversal/)
      // Fix the FS and retry; a fresh load must be attempted.
      escapingSymlink = false
      expect(await adapter.listPolicies()).toEqual([])
    })

    it('throws on non-ENOENT load failures instead of fail-opening to empty store', async () => {
      // EACCES, EISDIR, etc. must surface; an empty-store fallback would leave every decision to defaultEffect.
      const fs: IamFile.IFS = {
        async readFile() {
          throw Object.assign(new Error('EACCES'), { code: 'EACCES' })
        },
        async writeFile() {},
        async mkdir() {},
      }
      const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({ path: '/store.json', fs })
      await expect(adapter.listPolicies()).rejects.toThrow(/load failed \(EACCES\)/)
    })

    it('still treats genuinely-missing file as empty store (ENOENT)', async () => {
      const fs: IamFile.IFS = {
        async readFile() {
          throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
        },
        async writeFile() {},
        async mkdir() {},
      }
      const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({ path: '/store.json', fs })
      expect(await adapter.listPolicies()).toEqual([])
    })

    it('re-checks realpath on every I/O, not just the first', async () => {
      // After the first read the file is swapped for a symlink to /etc/passwd; the next write must re-check and reject.
      let realpathCalls = 0
      let swapped = false
      const fs: IamFile.IFS = {
        async readFile() {
          return JSON.stringify({ policies: {}, roles: {}, assignments: {}, attributes: {} })
        },
        async writeFile() {},
        async mkdir() {},
        async realpath(p: string): Promise<string> {
          realpathCalls++
          if (p === '/srv/iam/store.json') return swapped ? '/etc/passwd' : '/srv/iam/store.json'
          if (p === '/srv/iam') return '/srv/iam'
          throw new Error('ENOENT')
        },
      }
      const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({
        path: '/srv/iam/store.json',
        rootDir: '/srv/iam',
        fs,
      })
      // First read succeeds.
      await adapter.listPolicies()
      const callsAfterFirst = realpathCalls
      expect(callsAfterFirst).toBeGreaterThan(0)
      // Attacker swap.
      swapped = true
      // The write path runs `_assertWithinRoot` before writing, even though the load is served from cache.
      await expect(adapter.savePolicy({ id: 'p', name: 'p', algorithm: 'deny-overrides', rules: [] })).rejects.toThrow(
        /symlink traversal/,
      )
      expect(realpathCalls).toBeGreaterThan(callsAfterFirst)
    })

    it('does not call mkdir recursively (only the immediate parent)', async () => {
      // The immediate parent is pre-seeded so the non-recursive mkdir hits EEXIST; the grandparent is never touched.
      const fs = makeFakeFS(undefined, { storePath: '/srv/iam/store.json', preCreatedDirs: ['/srv/iam'] })
      const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({
        path: '/srv/iam/store.json',
        rootDir: '/srv/iam',
        fs,
      })
      await adapter.savePolicy(policy)
      // /srv was never created by the adapter.
      expect(fs.dirs.has('/srv')).toBe(false)
      // Parent was either pre-existing or EEXIST'd; either way the file is there.
      expect(fs.files.has('/srv/iam/store.json')).toBe(true)
    })
  })
})

describe('iamFileAdapter factory', () => {
  it('returns a working IamFileAdapter over the supplied FS', async () => {
    const adapter = iamFileAdapter({ fs: makeFakeFS(), path: '/store.json' })
    expect(adapter).toBeInstanceOf(IamFileAdapter)
    await adapter.saveRole({ id: 'viewer', name: 'Viewer', permissions: [] })
    await adapter.assignRole('user-1', 'viewer')
    expect(await adapter.getSubjectRoles('user-1')).toEqual(['viewer'])
  })

  it('propagates constructor validation (relative path still rejected)', () => {
    expect(() => iamFileAdapter({ fs: makeFakeFS(), path: 'relative.json' })).toThrow(/absolute path/)
  })
})
