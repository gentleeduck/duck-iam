import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../adapters/memory'
import { IamEngine } from '../../core/engine'
import type { AccessControl } from '../../core/types'
import { iamGuard as expressGuard } from '../express'
import { iamGuard as honoGuard } from '../hono'
import { IamAuthorize, iamNestAccessGuard } from '../nest'
import { createIamNextMiddleware, withIamAccess } from '../next'

/** The deny keys on the scope alone, so a check made with no scope cannot fire it. */
const POLICY: AccessControl.IPolicy = {
  algorithm: 'deny-overrides',
  description: '',
  id: 'posts',
  name: 'posts',
  rules: [
    {
      actions: ['read'],
      conditions: { all: [{ field: 'scope', operator: 'eq', value: 'org-1' }] },
      effect: 'deny',
      id: 'deny-org-1',
      priority: 100,
      resources: ['post'],
    },
    {
      actions: ['read'],
      conditions: { all: [] },
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

function nestCtx(params: Record<string, string>, staticScope?: string) {
  const handler = function read() {}
  IamAuthorize({ action: 'read', resource: 'post', ...(staticScope === undefined ? {} : { scope: staticScope }) })(
    {} as never,
    'read',
    { configurable: true, value: handler, writable: true },
  )
  return {
    getHandler: () => handler,
    switchToHttp: () => ({ getRequest: () => ({ headers: {}, method: 'GET', params, user: { id: 'u1' } }) }),
  }
}

/** `dynamic` wires `getScope` to read the org from the route; `staticScope` sets the fixed option. */
type Drive = { dynamic?: boolean; staticScope?: string; record?: (scope: string | undefined) => void }

const PARAMS = { id: '42', orgId: 'org-1' }
const URL_PATH = 'https://x.test/orgs/org-1/posts/42'
const orgFromUrl = (req: Request) => new URL(req.url).pathname.split('/')[2]

/** Each runner answers `true` when the read went through. The policy denies scope `org-1`. */
const GUARDS: { name: string; run: (engine: IamEngine, d: Drive) => Promise<boolean> }[] = [
  {
    name: 'express iamGuard',
    run: async (engine, d) => {
      let nexted = false
      await expressGuard(engine, 'read', 'post', {
        getResourceAttributes: (_req, ctx) => {
          d.record?.(ctx.scope)
          return {}
        },
        getScope: d.dynamic ? (req) => req.params?.orgId : undefined,
        getUserId: () => 'u1',
        scope: d.staticScope,
      })({ headers: {}, params: PARAMS } as never, res() as never, () => {
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
        req: {
          header: () => undefined,
          method: 'GET',
          param: (n: string) => PARAMS[n as keyof typeof PARAMS],
        },
      }
      await honoGuard(engine, 'read', 'post', {
        getResourceAttributes: (_c, ctx) => {
          d.record?.(ctx.scope)
          return {}
        },
        getScope: d.dynamic ? (ctx) => ctx.req.param('orgId') : undefined,
        getUserId: () => 'u1',
        scope: d.staticScope,
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
          d.record?.(ctx.scope)
          return {}
        },
        getScope: d.dynamic ? (req) => req.params?.orgId : undefined,
      })(nestCtx(PARAMS, d.staticScope) as never),
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
            d.record?.(ctx.scope)
            return {}
          },
          getScope: d.dynamic ? (_req, params) => params?.orgId : undefined,
          getUserId: () => 'u1',
          scope: d.staticScope,
        },
      )
      await wrapped(new Request(URL_PATH), { params: PARAMS })
      return ran
    },
  },
]

/** Middleware sees only the URL, so the org comes off the path. */
async function runMiddleware(engine: IamEngine, d: Drive): Promise<boolean> {
  const mw = createIamNextMiddleware(engine, {
    getResourceAttributes: (_req, ctx) => {
      d.record?.(ctx.scope)
      return {}
    },
    getScope: d.dynamic ? orgFromUrl : undefined,
    getUserId: () => 'u1',
    rules: [{ action: 'read', pattern: '/orgs', resource: 'post', scope: d.staticScope }],
  })
  return (await mw(new Request(URL_PATH))) === null
}

describe('a guard and the scope it runs under', () => {
  it.each(GUARDS)('$name runs unscoped by default, so a scope-conditioned deny misses', async ({ run }) => {
    expect(await run(await makeEngine(), {})).toBe(true)
  })

  it.each(GUARDS)('$name fires the deny once getScope names the org', async ({ run }) => {
    expect(await run(await makeEngine(), { dynamic: true })).toBe(false)
  })

  it.each(GUARDS)('$name still honours a fixed scope', async ({ run }) => {
    expect(await run(await makeEngine(), { staticScope: 'org-1' })).toBe(false)
  })

  it.each(GUARDS)('$name lets the fixed scope win over getScope', async ({ run }) => {
    expect(await run(await makeEngine(), { dynamic: true, staticScope: 'org-2' })).toBe(true)
  })

  it.each(GUARDS)('$name hands the resolved scope to the attribute loader', async ({ run }) => {
    const seen: (string | undefined)[] = []
    await run(await makeEngine(), { dynamic: true, record: (s) => seen.push(s) })
    expect(seen).toEqual(['org-1'])
  })

  it('createIamNextMiddleware runs unscoped until getScope is wired', async () => {
    expect(await runMiddleware(await makeEngine(), {})).toBe(true)
    expect(await runMiddleware(await makeEngine(), { dynamic: true })).toBe(false)
  })

  it('createIamNextMiddleware lets the rule’s own scope win, and reports the resolved one', async () => {
    expect(await runMiddleware(await makeEngine(), { dynamic: true, staticScope: 'org-2' })).toBe(true)
    const seen: (string | undefined)[] = []
    await runMiddleware(await makeEngine(), { dynamic: true, record: (s) => seen.push(s) })
    expect(seen).toEqual(['org-1'])
  })

  it('the deny is the engine’s: it fires on the scope and misses without one', async () => {
    const engine = await makeEngine()
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' }, undefined, 'org-1')).toBe(false)
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' })).toBe(true)
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' }, undefined, 'org-2')).toBe(true)
  })
})
