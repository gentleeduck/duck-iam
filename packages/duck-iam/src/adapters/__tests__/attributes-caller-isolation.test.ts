import { describe, expect, it } from 'vitest'
import type { IamPrimitives } from '../../core/types'
import { type IamFile, IamFileAdapter } from '../file'
import { IamMemoryAdapter } from '../memory'

// Memory and file must share no attribute bag, nested array or record with callers, on read, write or seed.
// NOTE: write-direction tests must keep the patch they pass; a `structuredClone`d argument cannot observe aliasing.

const ROOT = '/store'
const PATH = '/store/iam.json'

/** An in-memory `IFS`, so the file adapter runs its real load/flush path. */
function memFs(): IamFile.IFS {
  const files = new Map<string, string>()
  return {
    async mkdir() {
      return undefined
    },
    async readFile(path) {
      const v = files.get(path)
      if (v === undefined) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      return v
    },
    async rename(oldPath, newPath) {
      const v = files.get(oldPath)
      if (v === undefined) throw new Error('ENOENT')
      files.delete(oldPath)
      files.set(newPath, v)
    },
    async writeFile(path, data) {
      files.set(path, data)
    },
  }
}

const ADAPTERS: readonly (readonly [string, () => IamMemoryAdapter | IamFileAdapter])[] = [
  ['memory', () => new IamMemoryAdapter()],
  ['file', () => new IamFileAdapter({ fs: memFs(), path: PATH, rootDir: ROOT })],
]

const SEED: IamPrimitives.Attributes = { groups: ['staff'], suspended: false, tier: 'gold' }

for (const [name, make] of ADAPTERS) {
  describe(`${name}: getSubjectAttributes hands back a caller-owned copy`, () => {
    it('CONTROL: the seeded attributes are readable, so the assertions below mean something', async () => {
      const a = make()
      await a.setSubjectAttributes('u1', structuredClone(SEED))
      expect(await a.getSubjectAttributes('u1')).toEqual(SEED)
    })

    it('adding a key to the returned bag does not add it to the store', async () => {
      const a = make()
      await a.setSubjectAttributes('u1', structuredClone(SEED))
      Reflect.set(await a.getSubjectAttributes('u1'), 'admin', true)
      expect(await a.getSubjectAttributes('u1')).toEqual(SEED)
    })

    it('pushing to a returned array does not change the stored array', async () => {
      const a = make()
      await a.setSubjectAttributes('u1', structuredClone(SEED))
      const got = await a.getSubjectAttributes('u1')
      const groups = got.groups
      if (!Array.isArray(groups)) throw new Error('setup: groups should be an array')
      groups.push('admins')
      expect(await a.getSubjectAttributes('u1')).toEqual(SEED)
    })

    it('an edit to the returned bag is not committed by a later unrelated write', async () => {
      const a = make()
      await a.setSubjectAttributes('u1', structuredClone(SEED))
      Reflect.set(await a.getSubjectAttributes('u1'), 'admin', true)
      // A different subject; on the file adapter this flushes the whole state, which would make an alias durable.
      await a.setSubjectAttributes('u2', { tier: 'bronze' })
      expect(await a.getSubjectAttributes('u1')).toEqual(SEED)
    })

    it('two readers get separate objects', async () => {
      const a = make()
      await a.setSubjectAttributes('u1', structuredClone(SEED))
      const first = await a.getSubjectAttributes('u1')
      const second = await a.getSubjectAttributes('u1')
      expect(first).not.toBe(second)
      expect(first.groups).not.toBe(second.groups)
    })
  })
}

describe('the file adapter’s copy survives a reopen', () => {
  it('an edit to a returned bag never reaches disk', async () => {
    const fs = memFs()
    const a = new IamFileAdapter({ fs, path: PATH, rootDir: ROOT })
    await a.setSubjectAttributes('u1', structuredClone(SEED))
    Reflect.set(await a.getSubjectAttributes('u1'), 'admin', true)
    await a.setSubjectAttributes('u2', { tier: 'bronze' })

    // A second adapter over the same files reads only what was actually written.
    const reopened = new IamFileAdapter({ fs, path: PATH, rootDir: ROOT })
    expect(await reopened.getSubjectAttributes('u1')).toEqual(SEED)
  })
})

for (const [name, make] of ADAPTERS) {
  describe(`${name}: setSubjectAttributes keeps no handle on the caller's patch`, () => {
    it('CONTROL: the patch is actually stored, so the assertions below mean something', async () => {
      const a = make()
      await a.setSubjectAttributes('u1', { groups: ['staff'], tier: 'gold' })
      expect(await a.getSubjectAttributes('u1')).toEqual({ groups: ['staff'], tier: 'gold' })
    })

    it('pushing to an array the caller passed in does not change the stored array', async () => {
      const a = make()
      const patch: IamPrimitives.Attributes = { groups: ['staff'] }
      await a.setSubjectAttributes('u1', patch)
      const groups = patch.groups
      if (!Array.isArray(groups)) throw new Error('setup: groups should be an array')
      // SECURITY: `contains` conditions read `groups`, so a value appearing after the write is an unauthorised grant.
      groups.push('admins')
      expect(await a.getSubjectAttributes('u1')).toEqual({ groups: ['staff'] })
    })

    it('editing a record the caller passed in does not change the stored record', async () => {
      const a = make()
      const patch: IamPrimitives.Attributes = { limits: { seats: 1 } }
      await a.setSubjectAttributes('u1', patch)
      const limits = patch.limits
      if (typeof limits !== 'object' || limits === null || Array.isArray(limits)) {
        throw new Error('setup: limits should be a record')
      }
      Reflect.set(limits, 'seats', 999)
      expect(await a.getSubjectAttributes('u1')).toEqual({ limits: { seats: 1 } })
    })

    it('a mutated patch is not committed by a later unrelated write', async () => {
      const a = make()
      const patch: IamPrimitives.Attributes = { groups: ['staff'] }
      await a.setSubjectAttributes('u1', patch)
      const groups = patch.groups
      if (!Array.isArray(groups)) throw new Error('setup: groups should be an array')
      groups.push('admins')
      // On the file adapter this flushes the whole state, which would make an alias durable.
      await a.setSubjectAttributes('u2', { tier: 'bronze' })
      expect(await a.getSubjectAttributes('u1')).toEqual({ groups: ['staff'] })
    })
  })
}

describe('the memory adapter\u2019s constructor seed', () => {
  it('copies the seeded bags rather than storing the caller\u2019s objects', async () => {
    const seeded = { u1: { groups: ['staff'] } }
    const a = new IamMemoryAdapter({ attributes: seeded })

    expect(await a.getSubjectAttributes('u1')).toEqual({ groups: ['staff'] })

    // No write call is involved here: the store must not follow the caller's seed object.
    seeded.u1.groups.push('admins')
    expect(await a.getSubjectAttributes('u1')).toEqual({ groups: ['staff'] })
  })
})
