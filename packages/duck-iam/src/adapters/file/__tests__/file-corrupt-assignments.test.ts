import { describe, expect, it } from 'vitest'
import { IamEngine } from '../../../core/engine'
import { IamFile, IamFileAdapter } from '../index'

// A dropped role grant is not a smaller permission set: a policy targeting that role stops applying, so its
// deny stops firing. This file pins that a malformed assignments row fails closed, as a corrupt attributes row does.

const PATH = '/store.json'

function makeFs(initial: string): { fs: IamFile.IFS; read: () => string } {
  const files = new Map<string, string>([[PATH, initial]])
  return {
    fs: {
      async mkdir() {},
      async readFile(p: string) {
        const v = files.get(p)
        if (v === undefined) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
        return v
      },
      async writeFile(p: string, d: string) {
        files.set(p, d)
      },
    },
    read: () => files.get(PATH) ?? '',
  }
}

const ROLES = {
  banned: { id: 'banned', name: 'Banned', permissions: [] },
  reader: { id: 'reader', name: 'Reader', permissions: [{ action: 'read', resource: 'post' }] },
}

/** `reader` is what grants; `deny-banned` is what a lost `banned` grant would silently retire. */
const POLICIES = {
  'allow-all-read': {
    algorithm: 'deny-overrides',
    id: 'allow-all-read',
    name: 'allow read',
    rules: [
      { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r-allow', priority: 10, resources: ['post'] },
    ],
  },
  'deny-banned': {
    algorithm: 'deny-overrides',
    id: 'deny-banned',
    name: 'deny banned',
    rules: [
      { actions: ['read'], conditions: { all: [] }, effect: 'deny', id: 'r-deny', priority: 50, resources: ['post'] },
    ],
    targets: { roles: ['banned'] },
  },
}

function storeWith(assignments: unknown): string {
  return JSON.stringify({ assignments, attributes: {}, policies: POLICIES, roles: ROLES })
}

function adapterOn(fs: IamFile.IFS, reports: string[] = []) {
  return new IamFileAdapter({ fs, onPolicyError: (err) => reports.push(err.message), path: PATH, rootDir: '/' })
}

async function canRead(assignments: unknown): Promise<boolean> {
  const adapter = adapterOn(makeFs(storeWith(assignments)).fs)
  const engine = new IamEngine({ adapter, cacheTTL: 0 })
  return engine.can('u1', 'read', { attributes: {}, id: 'p1', type: 'post' })
}

/** Every way the loader can fail to read one `{role, scope?}` entry, plus a row that is not an array at all. */
const MALFORMED: Array<[string, unknown]> = [
  ['a non-string role', [{ role: 'reader' }, { role: 42 }]],
  ['a non-string scope', [{ role: 'reader' }, { role: 'banned', scope: 5 }]],
  ['an empty scope', [{ role: 'reader' }, { role: 'banned', scope: '' }]],
  ['an entry that is not an object', [{ role: 'reader' }, 'banned']],
  ['a row that is not an array', 'reader banned'],
]

describe('file adapter: a malformed assignments row fails closed', () => {
  // Positive control: the deny only means something because the allow it overrides really answers true.
  it('the same policy set allows the subject who is only a reader', async () => {
    expect(await canRead({ u1: [{ role: 'reader' }] })).toBe(true)
  })

  it('and denies once the banned grant is there to be found', async () => {
    expect(await canRead({ u1: [{ role: 'reader' }, { role: 'banned' }] })).toBe(false)
  })

  for (const [label, assignments] of MALFORMED) {
    it(`denies rather than losing the grant: ${label}`, async () => {
      expect(await canRead({ u1: assignments })).toBe(false)
    })

    it(`reports and refuses to read the row: ${label}`, async () => {
      const reports: string[] = []
      const adapter = adapterOn(makeFs(storeWith({ u1: assignments })).fs, reports)
      await expect(adapter.getSubjectRoles('u1')).rejects.toThrow(/corrupted assignments for "u1"/)
      await expect(adapter.getSubjectScopedRoles('u1')).rejects.toThrow(/corrupted assignments for "u1"/)
      expect(reports.join(' | ')).toContain('assignments[u1]')
    })
  }

  it('leaves every other subject readable', async () => {
    const adapter = adapterOn(makeFs(storeWith({ u1: [{ role: 42 }], u2: [{ role: 'reader' }] })).fs)
    await expect(adapter.getSubjectRoles('u1')).rejects.toThrow(/corrupted assignments/)
    expect(await adapter.getSubjectRoles('u2')).toEqual(['reader'])
  })

  it('writes the malformed row back verbatim, so a flush cannot repair it by deletion', async () => {
    const { fs, read } = makeFs(storeWith({ u1: [{ role: 'reader' }, { role: 42 }] }))
    const first = adapterOn(fs)
    // An unrelated write: before this fix it rewrote `assignments` from the parsed state, erasing the bad entry.
    await first.setSubjectAttributes('someone-else', { tier: 'gold' })
    expect(JSON.parse(read()).assignments.u1).toEqual([{ role: 'reader' }, { role: 42 }])

    const reloaded = adapterOn(fs)
    await expect(reloaded.getSubjectRoles('u1')).rejects.toThrow(/corrupted assignments/)
    expect(await canRead(JSON.parse(read()).assignments)).toBe(false)
  })

  it('refuses an assignment write against a row it cannot read, and still serves a clean subject', async () => {
    const { fs } = makeFs(storeWith({ u1: [{ role: 'reader' }, { role: 42 }], u2: [] }))
    const adapter = adapterOn(fs)
    await expect(adapter.assignRole('u1', 'banned')).rejects.toThrow(/corrupted assignments/)
    await expect(adapter.revokeRole('u1', 'reader')).rejects.toThrow(/corrupted assignments/)
    await expect(adapter.updateAssignmentScope('u1', 'reader', undefined, 'tenant-a')).rejects.toThrow(
      /corrupted assignments/,
    )
    await adapter.assignRole('u2', 'reader')
    expect(await adapter.getSubjectRoles('u2')).toEqual(['reader'])
  })

  it('reports the row deleteRole could not sweep, and still deletes the role', async () => {
    const reports: string[] = []
    const { fs } = makeFs(storeWith({ u1: [{ role: 'banned' }, { role: 42 }] }))
    const adapter = adapterOn(fs, reports)
    await adapter.deleteRole('banned')
    expect(await adapter.getRole('banned')).toBeNull()
    expect(reports.join(' | ')).toContain('was not swept')
  })
})
