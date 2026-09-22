import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl, IamRequest } from '../../types'
import { IamEngine } from '../engine'
import type { IamEngineTypes } from '../engine.types'

// `permissions()` keys by `resourceId`, so a caller reads the map as an answer about that instance. The verdict is
// only as precise as the attributes the check carries: with none, a rule on `resource.attributes.*` sees nothing.

const ARCHIVED_DENY: AccessControl.IPolicy = {
  algorithm: 'deny-overrides',
  description: '',
  id: 'posts',
  name: 'posts',
  rules: [
    {
      actions: ['read'],
      conditions: { all: [{ field: 'resource.attributes.archived', operator: 'eq', value: true }] },
      effect: 'deny',
      id: 'deny-archived',
      priority: 100,
      resources: ['post'],
    },
    {
      actions: ['read'],
      conditions: { all: [{ field: 'action', operator: 'eq', value: 'read' }] },
      effect: 'allow',
      id: 'allow-read',
      priority: 1,
      resources: ['post'],
    },
  ],
  version: 1,
}

const OWNER_ALLOW: AccessControl.IPolicy = {
  algorithm: 'deny-overrides',
  description: '',
  id: 'owned',
  name: 'owned',
  rules: [
    {
      actions: ['update'],
      conditions: { all: [{ field: 'resource.attributes.ownerId', operator: 'eq', value: '$subject.id' }] },
      effect: 'allow',
      id: 'allow-owner',
      priority: 10,
      resources: ['post'],
    },
  ],
  version: 1,
}

async function engineWith(policies: AccessControl.IPolicy[], hooks?: IamEngineTypes.IConfig['hooks']) {
  const adapter = new IamMemoryAdapter()
  await adapter.saveRole({
    description: '',
    id: 'reader',
    inherits: [],
    name: 'reader',
    permissions: [
      { action: 'read', resource: 'post' },
      { action: 'update', resource: 'post' },
    ],
  })
  await adapter.assignRole('u1', 'reader')
  for (const p of policies) await adapter.savePolicy(p)
  return new IamEngine({ adapter, cacheTTL: 0, mode: 'production', ...(hooks ? { hooks } : {}) })
}

describe('a permission check and the instance it names', () => {
  it('carries the attributes into the evaluation, so the map answers what can() answers', async () => {
    const engine = await engineWith([ARCHIVED_DENY])
    const resource = { attributes: { archived: true }, id: '42', type: 'post' }

    const direct = await engine.can('u1', 'read', resource)
    const map = await engine.permissions('u1', [
      { action: 'read', attributes: { archived: true }, resource: 'post', resourceId: '42' },
    ])

    expect(direct).toBe(false)
    expect(map['read:post:42']).toBe(false)
  })

  it('answers about a resource with no attributes when the check omits them', async () => {
    const engine = await engineWith([ARCHIVED_DENY])

    const map = await engine.permissions('u1', [{ action: 'read', resource: 'post', resourceId: '42' }])
    const onTheRealRow = await engine.can('u1', 'read', { attributes: { archived: true }, id: '42', type: 'post' })

    // Documented, not a bug: the key names the instance, the verdict does not know it is archived.
    expect(map['read:post:42']).toBe(true)
    expect(onTheRealRow).toBe(false)
  })

  it('grants on an attribute the same way, not only denies', async () => {
    const engine = await engineWith([OWNER_ALLOW])

    const withOwner = await engine.permissions('u1', [
      { action: 'update', attributes: { ownerId: 'u1' }, resource: 'post', resourceId: '42' },
    ])
    const withoutOwner = await engine.permissions('u1', [{ action: 'update', resource: 'post', resourceId: '42' }])
    const someoneElses = await engine.permissions('u1', [
      { action: 'update', attributes: { ownerId: 'u2' }, resource: 'post', resourceId: '42' },
    ])

    expect(withOwner['update:post:42']).toBe(true)
    expect(withoutOwner['update:post:42']).toBe(false)
    expect(someoneElses['update:post:42']).toBe(false)
  })

  it('hands the hooks the same resource it evaluated', async () => {
    const seen: IamRequest.IResource[] = []
    const engine = await engineWith([ARCHIVED_DENY], {
      afterEvaluate: (req) => {
        seen.push(req.resource)
      },
    })

    await engine.permissions('u1', [
      { action: 'read', attributes: { archived: true }, resource: 'post', resourceId: '42' },
    ])

    expect(seen).toHaveLength(1)
    expect(seen[0]?.attributes).toEqual({ archived: true })
  })

  it('does not let one check’s attributes reach another', async () => {
    const engine = await engineWith([ARCHIVED_DENY])

    const map = await engine.permissions('u1', [
      { action: 'read', attributes: { archived: true }, resource: 'post', resourceId: '42' },
      { action: 'read', resource: 'post', resourceId: '43' },
    ])

    expect(map['read:post:42']).toBe(false)
    expect(map['read:post:43']).toBe(true)
  })
})
