import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { IamAccessControl } from '../../../core/types'
import { runAdapterCompliance } from '../../__compliance__/compliance'
import { IamFile, IamFileAdapter } from '../index'

type Action = 'read' | 'write'
type Resource = 'post'
type Role = 'viewer' | 'editor'
type Scope = 'org-1'

type FakeFS = IamFile.IFS & {
  files: Map<string, string>
  dirs: Set<string>
  realpathMap?: Map<string, string>
}

function makeFakeFS(initial?: string, opts: { storePath?: string; preCreatedDirs?: string[] } = {}): FakeFS {
  const files = new Map<string, string>()
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

// IamAdapter compliance - fresh in-memory fake FS per call so each scenario
// runs against an empty store.
runAdapterCompliance('IamFileAdapter', () => new IamFileAdapter({ fs: makeFakeFS(), path: '/store.json' }) as never)

const policy: IamAccessControl.IPolicy<Action, Resource, Role> = {
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
    expect(await adapter.listPolicies()).toEqual([policy])
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
    await adapter.assignRole('user-1', 'viewer')
    expect(await adapter.getSubjectRoles('user-1')).toEqual(['viewer'])
  })

  it('scoped assignments are exposed via getSubjectScopedRoles only', async () => {
    const fs = makeFakeFS()
    const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({ path: '/store.json', fs })
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
    // Previous behaviour silently populated _cache = {} which the next
    // flush would persist, permanently destroying recoverable data.
    const fs = makeFakeFS('not-json{')
    const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({ path: '/store.json', fs })
    await expect(adapter.listPolicies()).rejects.toThrow(/corrupt.*refusing to load/)
  })

  describe('malformed-row drop (P0)', () => {
    // Same guarantee the IamRedis adapter provides: a corrupt row stored on
    // disk (manual edit, partial migration, etc) must be dropped, not
    // returned as-is. The engine's safeEval would otherwise treat it as
    // NotApplicable and silently strip any deny rules it would have carried.
    it('drops a policy entry that fails validation, keeps valid ones', async () => {
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
      const list = await adapter.listPolicies()
      expect(list.map((p) => p.id)).toEqual(['p1'])
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

    it('warns at most once per process when rootDir is omitted', () => {
      _warnSpy?.mockClear()
      const fs = makeFakeFS()
      // Latch is module-level: prior tests in this file may already have
      // tripped it, so the warn for these constructions may not fire at all.
      // Contract is `at most one` across multiple constructions, never per-
      // construction spam.
      new IamFileAdapter<Action, Resource, Role, Scope>({ path: '/store-1.json', fs })
      new IamFileAdapter<Action, Resource, Role, Scope>({ path: '/store-2.json', fs })
      new IamFileAdapter<Action, Resource, Role, Scope>({ path: '/store-3.json', fs })
      const rootDirWarns = (_warnSpy?.mock.calls ?? []).filter((c: unknown[]) => /rootDir/.test(String(c[0])))
      expect(rootDirWarns.length).toBeLessThanOrEqual(1)
    })

    it('does not reflect the constructed path in the rootDir-missing warn', () => {
      _warnSpy?.mockClear()
      const fs = makeFakeFS()
      const uniquePath = `/very-unique-path-${Date.now()}.json`
      new IamFileAdapter<Action, Resource, Role, Scope>({ path: uniquePath, fs })
      const rootDirWarns = (_warnSpy?.mock.calls ?? []).filter((c: unknown[]) => /rootDir/.test(String(c[0])))
      // Latch may already have fired in prior tests, so this assertion only
      // applies if a fresh warn did fire here.
      for (const call of rootDirWarns) {
        expect(String(call[0])).not.toContain(uniquePath)
      }
    })

    it('rejects a symlink that resolves outside rootDir (via realpath)', async () => {
      // Inject a fake realpath that mimics a symlink: /srv/iam/store.json is
      // actually a symlink to /etc/passwd on disk. The constructor's textual
      // check passes (path string is under rootDir) but the async realpath
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
      // A symlink-loop on the file (ELOOP) was previously silenced by the
      // parent-realpath fallback, letting a hostile symlink bypass the
      // containment check.
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
      // ENOENT (file genuinely missing on first run) keeps the legitimate
      // fallback alive - containment is asserted via the parent + basename.
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
      // The in-flight slot must clear on any throw so a fixed-up filesystem
      // can be re-tried; otherwise a rejected promise would pin the adapter
      // in permanent failure.
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
      // Fix the underlying FS state and retry - the in-flight slot must
      // have cleared so a fresh load is attempted.
      escapingSymlink = false
      expect(await adapter.listPolicies()).toEqual([])
    })

    it('throws on non-ENOENT load failures instead of fail-opening to empty store', async () => {
      // EACCES (permissions drift), EISDIR (path overwritten), etc. must
      // surface immediately. A silent empty-store fallback would let the
      // engine see zero policies and let defaultEffect decide every request.
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
      // After the first successful read, the file is swapped for a symlink to
      // /etc/passwd. The second I/O must re-run realpath and reject - the
      // one-shot _rootCheckDone latch would have let the symlink through.
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
      // Second op must re-run realpath and reject.
      // savePolicy clears the cache so _loadState will re-invoke _assertWithinRoot.
      await expect(adapter.savePolicy({ id: 'p', name: 'p', algorithm: 'deny-overrides', rules: [] })).rejects.toThrow(
        /symlink traversal/,
      )
      expect(realpathCalls).toBeGreaterThan(callsAfterFirst)
    })

    it('does not call mkdir recursively (only the immediate parent)', async () => {
      // Pre-seed the immediate parent so the non-recursive mkdir EEXISTs and
      // succeeds; the grandparent is never touched.
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
