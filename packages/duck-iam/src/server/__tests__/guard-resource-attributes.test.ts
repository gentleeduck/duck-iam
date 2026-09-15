import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../adapters/memory'
import { IamEngine } from '../../core/engine'
import type { AccessControl, IamPrimitives } from '../../core/types'
import { iamGuard as expressGuard, iamAccessMiddleware as expressMiddleware } from '../express'
import { createIamSubjectCan } from '../generic'
import { iamGuard as honoGuard } from '../hono'
import { IamAuthorize, iamNestAccessGuard } from '../nest'
import { checkIamAccess, createIamNextMiddleware, withIamAccess } from '../next'

// A guard runs before the handler loads the row, so the resource it evaluates carries whatever the caller supplies
// and nothing else. Every integration must offer a way to supply it, and must agree about what happens without one.

const ARCHIVED: IamPrimitives.Attributes = { archived: true }

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

function expressRes() {
  let status = 0
  return {
    get status() {
      return status
    },
    res: {
      json: () => {},
      status(code: number) {
        status = code
        return this
      },
    },
  }
}

function nestCtx() {
  const handler = function read() {}
  IamAuthorize({ action: 'read', resource: 'post' })({} as never, 'read', {
    configurable: true,
    value: handler,
    writable: true,
  })
  return {
    getHandler: () => handler,
    switchToHttp: () => ({
      getRequest: () => ({ headers: {}, method: 'GET', params: { id: '42' }, user: { id: 'u1' } }),
    }),
  }
}

/** Each entry answers "did this surface let the read through?", with and without the row's attributes. */
const SURFACES: { name: string; run: (engine: IamEngine, attrs?: IamPrimitives.Attributes) => Promise<boolean> }[] = [
  {
    name: 'express iamGuard',
    run: async (engine, attrs) => {
      let nexted = false
      const { res } = expressRes()
      await expressGuard(engine, 'read', 'post', {
        getUserId: () => 'u1',
        ...(attrs ? { getResourceAttributes: () => attrs } : {}),
      })({ headers: {}, params: { id: '42' } } as never, res as never, () => {
        nexted = true
      })
      return nexted
    },
  },
  {
    name: 'express iamAccessMiddleware',
    run: async (engine, attrs) => {
      let nexted = false
      const { res } = expressRes()
      await expressMiddleware(engine, {
        getAction: () => 'read',
        // The only surface that takes them synchronously: whatever an earlier middleware attached.
        getResource: () => ({ attributes: attrs ?? {}, id: '42', type: 'post' }),
        getUserId: () => 'u1',
      })({ headers: {}, method: 'GET', params: { id: '42' }, url: '/posts/42' } as never, res as never, () => {
        nexted = true
      })
      return nexted
    },
  },
  {
    name: 'hono iamGuard',
    run: async (engine, attrs) => {
      let nexted = false
      const c = {
        json: (data: unknown, code?: number) => ({ code, data }) as unknown as Response,
        req: { header: () => undefined, method: 'GET', param: (n: string) => (n === 'id' ? '42' : undefined) },
      }
      await honoGuard(engine, 'read', 'post', {
        getUserId: () => 'u1',
        ...(attrs ? { getResourceAttributes: () => attrs } : {}),
      })(c as never, async () => {
        nexted = true
      })
      return nexted
    },
  },
  {
    name: 'nest iamNestAccessGuard',
    run: async (engine, attrs) =>
      iamNestAccessGuard(engine, attrs ? { getResourceAttributes: () => attrs } : {})(nestCtx() as never),
  },
  {
    name: 'next withIamAccess',
    run: async (engine, attrs) => {
      let ran = false
      const wrapped = withIamAccess(
        engine,
        'read',
        'post',
        async () => {
          ran = true
          return Response.json({ ok: true })
        },
        { getUserId: () => 'u1', ...(attrs ? { getResourceAttributes: () => attrs } : {}) },
      )
      await wrapped(new Request('https://x.test/posts/42'), { params: { id: '42' } })
      return ran
    },
  },
  {
    name: 'next createIamNextMiddleware',
    run: async (engine, attrs) => {
      const mw = createIamNextMiddleware(engine, {
        getUserId: () => 'u1',
        rules: [{ action: 'read', pattern: '/posts', resource: 'post' }],
        ...(attrs ? { getResourceAttributes: () => attrs } : {}),
      })
      return (await mw(new Request('https://x.test/posts/42'))) === null
    },
  },
  {
    name: 'next checkIamAccess',
    run: (engine, attrs) => checkIamAccess(engine, 'u1', 'read', 'post', '42', undefined, undefined, attrs),
  },
  {
    name: 'generic createIamSubjectCan',
    run: (engine, attrs) => createIamSubjectCan(engine, 'u1')('read', 'post', '42', undefined, attrs),
  },
]

describe('a guard and the row it has not loaded', () => {
  it.each(SURFACES)('$name lets the archived post through when nothing names it', async ({ run }) => {
    const engine = await makeEngine()
    expect(await run(engine)).toBe(true)
  })

  it.each(SURFACES)('$name refuses once the attributes are supplied', async ({ run }) => {
    const engine = await makeEngine()
    expect(await run(engine, ARCHIVED)).toBe(false)
  })

  it('the deny is the engine’s, not the integration’s', async () => {
    const engine = await makeEngine()
    expect(await engine.can('u1', 'read', { attributes: ARCHIVED, id: '42', type: 'post' })).toBe(false)
    expect(await engine.can('u1', 'read', { attributes: {}, id: '42', type: 'post' })).toBe(true)
  })
})
