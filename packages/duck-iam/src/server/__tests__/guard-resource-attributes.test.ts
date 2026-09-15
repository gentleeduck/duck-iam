import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../adapters/memory'
import { IamEngine } from '../../core/engine'
import type { AccessControl } from '../../core/types'
import { iamGuard as expressGuard } from '../express'
import { createIamSubjectCan } from '../generic'
import { iamGuard as honoGuard } from '../hono'
import { checkIamAccess } from '../next'

// A route guard runs before the handler loads the row, so it evaluates a resource that has only a type and an id.
// A rule conditioned on `resource.attributes.*` cannot fire there. Documented in `docs/reference/server.md`;
// these tests exist so the four integrations cannot drift apart or change it unnoticed.

const POLICY: AccessControl.IPolicy = {
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

async function makeEngine() {
  const adapter = new IamMemoryAdapter()
  await adapter.saveRole({
    description: '',
    id: 'reader',
    inherits: [],
    name: 'reader',
    permissions: [{ action: 'read', resource: 'post' }],
  })
  await adapter.assignRole('u1', 'reader')
  await adapter.savePolicy(POLICY)
  return new IamEngine({ adapter, cacheTTL: 0, mode: 'production' })
}

const ARCHIVED = { attributes: { archived: true }, id: '42', type: 'post' }

describe('a route guard and the row it has not loaded', () => {
  it('express lets the archived post through, and can() on the loaded row still refuses', async () => {
    const engine = await makeEngine()
    let nexted = false
    let status = 0
    const res = {
      json: () => {},
      status(code: number) {
        status = code
        return this
      },
    }
    const mw = expressGuard(engine, 'read', 'post', { getUserId: () => 'u1' })
    await mw({ headers: {}, params: { id: '42' } } as never, res as never, () => {
      nexted = true
    })

    expect({ nexted, status }).toEqual({ nexted: true, status: 0 })
    expect(await engine.can('u1', 'read', ARCHIVED)).toBe(false)
  })

  it('hono answers the same', async () => {
    const engine = await makeEngine()
    let nexted = false
    const ctx = {
      json: (data: unknown, code?: number) => ({ code, data }) as unknown as Response,
      req: { header: () => undefined, method: 'GET', param: (n: string) => (n === 'id' ? '42' : undefined) },
    }
    await honoGuard(engine, 'read', 'post', { getUserId: () => 'u1' })(ctx as never, async () => {
      nexted = true
    })

    expect(nexted).toBe(true)
  })

  it('the next helper and the generic checker answer the same', async () => {
    const engine = await makeEngine()

    expect(await checkIamAccess(engine, 'u1', 'read', 'post', '42')).toBe(true)
    expect(await createIamSubjectCan(engine, 'u1')('read', 'post', '42')).toBe(true)
  })

  it('the deny is real: every path refuses once the attributes are supplied', async () => {
    const engine = await makeEngine()

    expect(await engine.can('u1', 'read', ARCHIVED)).toBe(false)
    const map = await engine.permissions('u1', [
      { action: 'read', attributes: { archived: true }, resource: 'post', resourceId: '42' },
    ])
    expect(map['read:post:42']).toBe(false)
  })
})
