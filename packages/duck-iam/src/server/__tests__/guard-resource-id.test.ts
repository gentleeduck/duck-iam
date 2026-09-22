import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../adapters/memory'
import { IamEngine } from '../../core/engine'
import type { AccessControl, IamPrimitives } from '../../core/types'
import { iamGuard as expressGuard } from '../express'
import { iamGuard as honoGuard } from '../hono'
import { IamAuthorize, iamNestAccessGuard } from '../nest'
import { checkIamAccess, createIamNextMiddleware, withIamAccess } from '../next'

const POLICY: AccessControl.IPolicy = {
  algorithm: 'deny-overrides',
  description: '',
  id: 'posts',
  name: 'posts',
  rules: [
    {
      actions: ['read'],
      conditions: { all: [{ field: 'resource.id', operator: 'eq', value: '42' }] },
      effect: 'deny',
      id: 'deny-42',
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

const res = () => ({
  json: () => {},
  status() {
    return this
  },
})

function nestCtx(params: Record<string, string>) {
  const handler = function read() {}
  IamAuthorize({ action: 'read', resource: 'post' })({} as never, 'read', {
    configurable: true,
    value: handler,
    writable: true,
  })
  return {
    getHandler: () => handler,
    switchToHttp: () => ({ getRequest: () => ({ headers: {}, method: 'GET', params, user: { id: 'u1' } }) }),
  }
}

/** `param` is where the post's id sits on the route; `override` wires `getResourceId` to read it. */
type Drive = { param: 'id' | 'postId'; override?: boolean; record?: (id: string | undefined) => void }

/** Each runner answers `true` when the read went through. The policy denies post 42, so `true` means it went unnamed. */
const GUARDS: { name: string; run: (engine: IamEngine, d: Drive) => Promise<boolean> }[] = [
  {
    name: 'express iamGuard',
    run: async (engine, d) => {
      let nexted = false
      await expressGuard(engine, 'read', 'post', {
        getResourceAttributes: (_req, ctx) => {
          d.record?.(ctx.resourceId)
          return {}
        },
        getResourceId: d.override ? (req) => req.params?.postId : undefined,
        getUserId: () => 'u1',
      })({ headers: {}, params: { [d.param]: '42' } } as never, res() as never, () => {
        nexted = true
      })
      return nexted
    },
  },
  {
    name: 'hono iamGuard',
    run: async (engine, d) => {
      let nexted = false
      const c = {
        json: (data: unknown, code?: number) => ({ code, data }) as unknown as Response,
        req: { header: () => undefined, method: 'GET', param: (n: string) => (n === d.param ? '42' : undefined) },
      }
      await honoGuard(engine, 'read', 'post', {
        getResourceAttributes: (_c, ctx) => {
          d.record?.(ctx.resourceId)
          return {}
        },
        getResourceId: d.override ? (ctx) => ctx.req.param('postId') : undefined,
        getUserId: () => 'u1',
      })(c as never, async () => {
        nexted = true
      })
      return nexted
    },
  },
  {
    name: 'nest iamNestAccessGuard',
    run: (engine, d) =>
      iamNestAccessGuard(engine, {
        getResourceAttributes: (_req, ctx) => {
          d.record?.(ctx.resourceId)
          return {}
        },
        getResourceId: d.override ? (req) => req.params?.postId : undefined,
      })(nestCtx({ [d.param]: '42' }) as never),
  },
  {
    name: 'next withIamAccess',
    run: async (engine, d) => {
      let ran = false
      const wrapped = withIamAccess(
        engine,
        'read',
        'post',
        async () => {
          ran = true
          return Response.json({})
        },
        {
          getResourceAttributes: (_req, ctx) => {
            d.record?.(ctx.resourceId)
            return {}
          },
          getResourceId: d.override ? (_req, params) => params?.postId : undefined,
          getUserId: () => 'u1',
        },
      )
      await wrapped(new Request('https://x.test/posts/42'), { params: { [d.param]: '42' } })
      return ran
    },
  },
]

/** Middleware sees only the URL, so it is driven by path shape, not by a param name. */
async function runMiddleware(engine: IamEngine, d: Omit<Drive, 'param'>): Promise<boolean> {
  const mw = createIamNextMiddleware(engine, {
    getResourceAttributes: (_req, ctx) => {
      d.record?.(ctx.resourceId)
      return {}
    },
    getResourceId: d.override ? (req) => new URL(req.url).pathname.split('/').pop() : undefined,
    getUserId: () => 'u1',
    rules: [{ action: 'read', pattern: '/posts', resource: 'post' }],
  })
  return (await mw(new Request('https://x.test/posts/42'))) === null
}

describe('a guard and the instance it names', () => {
  it.each(GUARDS)('$name refuses post 42 when the id is the route’s :id', async ({ run }) => {
    expect(await run(await makeEngine(), { param: 'id' })).toBe(false)
  })

  it.each(GUARDS)('$name lets post 42 through when the route calls it :postId', async ({ run }) => {
    expect(await run(await makeEngine(), { param: 'postId' })).toBe(true)
  })

  it.each(GUARDS)('$name refuses it once getResourceId names that param', async ({ run }) => {
    expect(await run(await makeEngine(), { override: true, param: 'postId' })).toBe(false)
  })

  it.each(GUARDS)('$name hands the resolved id to the attribute loader', async ({ run }) => {
    const seen: (string | undefined)[] = []
    await run(await makeEngine(), { override: true, param: 'postId', record: (id) => seen.push(id) })
    expect(seen).toEqual(['42'])
  })

  it('createIamNextMiddleware names no instance until getResourceId is wired', async () => {
    expect(await runMiddleware(await makeEngine(), {})).toBe(true)
    expect(await runMiddleware(await makeEngine(), { override: true })).toBe(false)
  })

  it('createIamNextMiddleware hands the resolved id to the attribute loader', async () => {
    const seen: (string | undefined)[] = []
    await runMiddleware(await makeEngine(), { override: true, record: (id) => seen.push(id) })
    expect(seen).toEqual(['42'])
  })

  it('the deny is the engine’s: an unnamed instance is allowed, and the argument helpers always name one', async () => {
    const engine = await makeEngine()
    expect(await engine.can('u1', 'read', { attributes: {}, id: '42', type: 'post' })).toBe(false)
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' })).toBe(true)
    expect(await checkIamAccess(engine, 'u1', 'read', 'post', '42')).toBe(false)
  })
})
