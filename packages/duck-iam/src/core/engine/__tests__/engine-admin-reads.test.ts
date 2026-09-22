import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

// The positive half of `engine-admin-input-validation`: those cases pin what the readers refuse,
// and until now the only proof they return anything ran behind Docker.

const ROLE: AccessControl.IRole = { id: 'editor', name: 'Editor', permissions: [{ action: 'read', resource: 'post' }] }
const POLICY: AccessControl.IPolicy = {
  algorithm: 'deny-overrides',
  id: 'p1',
  name: 'P',
  rules: [{ actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 10, resources: ['post'] }],
}

function buildEngine() {
  const adapter = new IamMemoryAdapter<string, string, string, string>({ roles: [ROLE] })
  const engine = new IamEngine<string, string, string, string, 'production'>({
    adapter,
    defaultEffect: 'deny',
    mode: 'production',
  })
  return { adapter, engine }
}

describe('engine.admin readers return what was written', () => {
  it('getRole returns the stored role', async () => {
    const { engine } = buildEngine()

    expect(await engine.admin.getRole('editor')).toEqual(ROLE)
  })

  it('getRole returns null for an id nothing is stored under', async () => {
    const { engine } = buildEngine()

    expect(await engine.admin.getRole('nobody')).toBeNull()
  })

  it('getPolicy returns the policy that was saved, with the version the store defaults', async () => {
    const { engine } = buildEngine()
    await engine.admin.savePolicy(POLICY)

    expect(await engine.admin.getPolicy('p1')).toEqual({ ...POLICY, version: 1 })
  })

  it('getPolicy returns null for an id nothing is stored under', async () => {
    const { engine } = buildEngine()

    expect(await engine.admin.getPolicy('missing')).toBeNull()
  })

  it('getRole reads a role saved through admin, not only a seeded one', async () => {
    const { engine } = buildEngine()
    const viewer: AccessControl.IRole = { id: 'viewer', name: 'Viewer', permissions: [] }
    await engine.admin.saveRole(viewer)

    expect(await engine.admin.getRole('viewer')).toEqual(viewer)
  })

  it('getAttributes returns the bag that was set', async () => {
    const { engine } = buildEngine()
    await engine.admin.setAttributes('u1', { tier: 'pro' })

    expect(await engine.admin.getAttributes('u1')).toEqual({ tier: 'pro' })
  })

  it('getAttributes returns an empty bag for a subject with none', async () => {
    const { engine } = buildEngine()

    expect(await engine.admin.getAttributes('u-none')).toEqual({})
  })

  it('a role the reader handed back is not the stored one', async () => {
    const { engine } = buildEngine()
    const read = await engine.admin.getRole('editor')
    if (!Array.isArray(read?.permissions)) throw new Error('expected permissions to read back')
    read.permissions.push({ action: 'delete', resource: '*' })

    expect((await engine.admin.getRole('editor'))?.permissions).toEqual(ROLE.permissions)
  })
})
