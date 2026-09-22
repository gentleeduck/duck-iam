import { describe, expect, it } from 'vitest'
import { IamEngine } from '../../../core/engine/engine'
import { type IamFile, IamFileAdapter } from '../index'

// Pins that a failed write leaves no grant in memory and is not persisted by a later write.
// `file-atomic-write.test.ts` covers the on-disk side; this covers what the adapter and engine answer.
const ROOT = '/store'
const PATH = '/store/iam.json'
const ADMIN = { id: 'admin', name: 'admin', permissions: [{ action: 'read', resource: 'post' }] }

function breakableFs() {
  const files = new Map<string, string>()
  let broken = false
  const fs: IamFile.IFS = {
    async mkdir() {
      return undefined
    },
    async readFile(path) {
      const v = files.get(path)
      if (v === undefined) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      return v
    },
    async rename(oldPath, newPath) {
      if (broken) throw Object.assign(new Error('ENOSPC'), { code: 'ENOSPC' })
      const v = files.get(oldPath)
      if (v === undefined) throw new Error('ENOENT')
      files.delete(oldPath)
      files.set(newPath, v)
    },
    async writeFile(path, data) {
      files.set(path, data)
    },
  }
  return { break: () => (broken = true), files, fix: () => (broken = false), fs }
}

/** Assignments as they are on disk, keyed by subject. */
function diskAssignments(files: Map<string, string>): Record<string, unknown> {
  const parsed: unknown = JSON.parse(files.get(PATH) ?? '{}')
  const a = parsed === null || typeof parsed !== 'object' ? undefined : Reflect.get(parsed, 'assignments')
  return a === null || typeof a !== 'object' ? {} : { ...a }
}

describe('a write the store refused leaves no grant behind', () => {
  it('the driver really does refuse the write', async () => {
    // Control: without it every assertion below could pass on an adapter that never wrote anything.
    const { break: brk, files, fs } = breakableFs()
    const a = new IamFileAdapter({ fs, path: PATH, rootDir: ROOT })
    await a.saveRole(ADMIN)
    await a.assignRole('u1', 'admin')
    expect(Object.keys(diskAssignments(files))).toEqual(['u1'])

    brk()
    await expect(a.assignRole('u2', 'admin')).rejects.toThrow('ENOSPC')
    expect(Object.keys(diskAssignments(files))).toEqual(['u1'])
  })

  it('the adapter does not answer with the refused grant', async () => {
    const { break: brk, fs } = breakableFs()
    const a = new IamFileAdapter({ fs, path: PATH, rootDir: ROOT })
    await a.saveRole(ADMIN)

    brk()
    await expect(a.assignRole('u2', 'admin')).rejects.toThrow('ENOSPC')
    expect(await a.getSubjectRoles('u2')).toEqual([])
  })

  it('a later successful write does not commit the refused grant', async () => {
    const { break: brk, files, fix, fs } = breakableFs()
    const a = new IamFileAdapter({ fs, path: PATH, rootDir: ROOT })
    await a.saveRole(ADMIN)
    await a.assignRole('u1', 'admin')

    brk()
    await expect(a.assignRole('u2', 'admin')).rejects.toThrow('ENOSPC')
    fix()
    // An unrelated subject. Nothing about this call mentions u2.
    await a.assignRole('u3', 'admin')

    expect(Object.keys(diskAssignments(files)).sort()).toEqual(['u1', 'u3'])
  })

  it('a reopened adapter and the original agree on who has the role', async () => {
    const { break: brk, files, fix, fs } = breakableFs()
    const a = new IamFileAdapter({ fs, path: PATH, rootDir: ROOT })
    await a.saveRole(ADMIN)
    await a.assignRole('u1', 'admin')

    brk()
    await expect(a.assignRole('u2', 'admin')).rejects.toThrow('ENOSPC')
    fix()
    await a.assignRole('u3', 'admin')

    const reopened = new IamFileAdapter({ fs, path: PATH, rootDir: ROOT })
    for (const subject of ['u1', 'u2', 'u3']) {
      expect(await a.getSubjectRoles(subject), `original disagrees about ${subject}`).toEqual(
        await reopened.getSubjectRoles(subject),
      )
    }
    expect(await reopened.getSubjectRoles('u2')).toEqual([])
    // Not a suite that passes because nobody has the role.
    expect(await reopened.getSubjectRoles('u1')).toEqual(['admin'])
  })

  it('the engine denies the subject whose grant was refused', async () => {
    const { break: brk, fs } = breakableFs()
    const adapter = new IamFileAdapter<'read', 'post', string, string>({ fs, path: PATH, rootDir: ROOT })
    await adapter.saveRole({ id: 'admin', name: 'admin', permissions: [{ action: 'read', resource: 'post' }] })
    const engine = new IamEngine<'read', 'post', string, string>({ adapter })

    await adapter.assignRole('u1', 'admin')
    // Liveness: the engine can see a grant that did land.
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' })).toBe(true)

    brk()
    await expect(adapter.assignRole('u2', 'admin')).rejects.toThrow('ENOSPC')
    expect(await engine.can('u2', 'read', { attributes: {}, type: 'post' })).toBe(false)
  })
})
