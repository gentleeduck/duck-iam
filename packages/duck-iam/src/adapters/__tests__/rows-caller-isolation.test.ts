import { describe, expect, it } from 'vitest'
import type { AccessControl } from '../../core/types'
import { type IamFile, IamFileAdapter } from '../file'
import { IamMemoryAdapter } from '../memory'

// The row half of `attributes-caller-isolation`: memory and file must share no policy, role, rule
// or permission with callers, on read, write or seed. A kept object re-writes the store on later edits,
// past the save-time validation that refused it.

const ROOT = '/store'
const PATH = '/store/iam.json'

/** An in-memory `IFS`, so the file adapter runs its real load/flush path. */
function memFs(): IamFile.IFS & { files: Map<string, string> } {
  const files = new Map<string, string>()
  return {
    files,
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

/** The stored arrays are `readonly` in the types only; this is the runtime edit a caller can still make. */
function pushAtRuntime<T>(list: readonly T[] | undefined, item: T): void {
  if (!Array.isArray(list)) throw new Error('expected an array to edit')
  list.push(item)
}

const ROLE: AccessControl.IRole = { id: 'editor', name: 'Editor', permissions: [{ action: 'read', resource: 'post' }] }
const POLICY: AccessControl.IPolicy = {
  algorithm: 'deny-overrides',
  id: 'p1',
  name: 'P',
  rules: [{ actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 10, resources: ['post'] }],
}
/** A rule `iamAssertSavablePolicy` never saw, standing in for anything an edit could smuggle in. */
const INJECTED: AccessControl.IRule = {
  actions: ['delete'],
  conditions: { all: [] },
  effect: 'allow',
  id: 'injected',
  priority: 99,
  resources: ['*'],
}

for (const [name, make] of ADAPTERS) {
  describe(`${name}: a stored row is not the caller's object`, () => {
    it('CONTROL: the saved row reads back, so the assertions below mean something', async () => {
      const a = make()
      await a.saveRole(structuredClone(ROLE))
      await a.savePolicy(structuredClone(POLICY))

      expect(await a.getRole('editor')).toEqual(ROLE)
      expect((await a.getPolicy('p1'))?.rules.map((r) => r.id)).toEqual(['r1'])
    })

    it('editing the role after saveRole leaves the store alone', async () => {
      const a = make()
      const role = structuredClone(ROLE)
      await a.saveRole(role)
      pushAtRuntime(role.permissions, { action: 'delete', resource: '*' })

      expect((await a.getRole('editor'))?.permissions).toEqual(ROLE.permissions)
    })

    it('editing the policy after savePolicy leaves the store alone', async () => {
      const a = make()
      const policy = structuredClone(POLICY)
      await a.savePolicy(policy)
      pushAtRuntime(policy.rules, INJECTED)

      expect((await a.getPolicy('p1'))?.rules.map((r) => r.id)).toEqual(['r1'])
      expect((await a.listPolicies())[0]?.rules.map((r) => r.id)).toEqual(['r1'])
    })

    it('editing what getRole returned leaves the store alone', async () => {
      const a = make()
      await a.saveRole(structuredClone(ROLE))
      const read = await a.getRole('editor')
      pushAtRuntime(read?.permissions, { action: 'delete', resource: '*' })

      expect((await a.getRole('editor'))?.permissions).toEqual(ROLE.permissions)
    })

    it('editing what getPolicy and listPolicies returned leaves the store alone', async () => {
      const a = make()
      await a.savePolicy(structuredClone(POLICY))
      const read = await a.getPolicy('p1')
      pushAtRuntime(read?.rules, INJECTED)
      const listed = await a.listPolicies()
      pushAtRuntime(listed[0]?.rules, INJECTED)

      expect((await a.getPolicy('p1'))?.rules.map((r) => r.id)).toEqual(['r1'])
    })

    it('editing what listRoles returned leaves the store alone', async () => {
      const a = make()
      await a.saveRole(structuredClone(ROLE))
      const listed = await a.listRoles()
      pushAtRuntime(listed[0]?.permissions, { action: 'delete', resource: '*' })

      expect((await a.getRole('editor'))?.permissions).toEqual(ROLE.permissions)
    })
  })
}

describe('memory: a seeded row is not the caller object either', () => {
  it('editing the seed after construction leaves the store alone', async () => {
    const role = structuredClone(ROLE)
    const a = new IamMemoryAdapter({ roles: [role] })
    pushAtRuntime(role.permissions, { action: 'delete', resource: '*' })

    expect((await a.getRole('editor'))?.permissions).toEqual(ROLE.permissions)
  })
})

describe('file: an edit made after the save does not reach the disk', () => {
  it('the next unrelated write persists the stored policy, not the edited one', async () => {
    const fs = memFs()
    const a = new IamFileAdapter({ fs, path: PATH, rootDir: ROOT })
    const policy = structuredClone(POLICY)
    await a.savePolicy(policy)
    pushAtRuntime(policy.rules, INJECTED)

    await a.saveRole(structuredClone(ROLE))
    const onDisk = JSON.parse(fs.files.get(PATH) ?? '{}')

    expect(onDisk.policies.p1.rules.map((r: AccessControl.IRule) => r.id)).toEqual(['r1'])
  })
})
