import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../adapters/memory'
import { IamEngine } from '../../core/engine'
import { iamGuard as expressGuard, iamAccessMiddleware as expressMiddleware } from '../express'
import { iamExtractEnvironment } from '../generic'
import { iamAccessMiddleware as honoMiddleware } from '../hono'
import { createIamAdminOperations, IamAuthorize, iamNestAccessGuard } from '../nest'
import { withIamAccess } from '../next'

// `getUserId` often does I/O, so its failure must reach each adapter's own `onError`.
// INFO: Express 4 does not catch a rejected middleware promise, so the client would hang.
const boom = () => {
  throw new Error('idp down')
}

function engine() {
  const adapter = new IamMemoryAdapter({
    assignments: { u1: ['viewer'] },
    roles: [{ id: 'viewer', name: 'Viewer', permissions: [{ action: 'read', resource: 'post' }] }],
  })
  return new IamEngine({ adapter, cacheTTL: 0 })
}

function expressRes() {
  return {
    body: undefined as unknown,
    json(body: unknown) {
      this.body = body
    },
    status(code: number) {
      this.statusCode = code
      return this
    },
    statusCode: 0,
  }
}

describe('a throwing getUserId denies through the adapter, not the framework', () => {
  it('express middleware answers 500 instead of rejecting', async () => {
    const mw = expressMiddleware(engine(), { getUserId: boom })
    const res = expressRes()
    const next = vi.fn()
    await expect(
      mw({ method: 'GET', path: '/post' } as Parameters<typeof mw>[0], res as Parameters<typeof mw>[1], next),
    ).resolves.toBeUndefined()
    expect(res.statusCode).toBe(500)
    expect(next).not.toHaveBeenCalled()
  })

  it('express guard answers 500 instead of rejecting', async () => {
    const mw = expressGuard(engine(), 'read', 'post', { getUserId: boom })
    const res = expressRes()
    await expect(
      mw({ method: 'GET', path: '/post' } as Parameters<typeof mw>[0], res as Parameters<typeof mw>[1], vi.fn()),
    ).resolves.toBeUndefined()
    expect(res.statusCode).toBe(500)
  })

  it('hono routes it to onError', async () => {
    const onError = vi.fn((_err: Error) => new Response(null, { status: 500 }))
    const mw = honoMiddleware(engine(), { getUserId: boom, onError })
    const ctx = {
      get: () => undefined,
      json: (data: unknown, status = 200) => new Response(JSON.stringify(data), { status }),
      req: {
        header: () => undefined,
        method: 'GET',
        param: () => undefined,
        path: '/post',
        url: 'https://example.com/post',
      },
      set: () => undefined,
      text: (data: string, status = 200) => new Response(data, { status }),
    }
    await mw(ctx, async () => undefined)
    expect(onError).toHaveBeenCalledOnce()
    expect(onError.mock.calls[0]?.[0]?.message).toBe('idp down')
  })

  it('nest routes it to onError and denies', async () => {
    const onError = vi.fn(() => false)
    const guard = iamNestAccessGuard(engine(), { getUserId: boom, onError })
    const handler = function route() {
      return null
    }
    IamAuthorize({ action: 'read', resource: 'post' })({} as never, 'route', {
      configurable: true,
      value: handler,
      writable: true,
    })
    const ctx = {
      getHandler: () => handler,
      switchToHttp: () => ({ getRequest: () => ({ method: 'GET', params: {}, path: '/post' }) }),
    }
    expect(await guard(ctx)).toBe(false)
    expect(onError).toHaveBeenCalledOnce()
  })

  it('next routes it to onError', async () => {
    const onError = vi.fn(() => Response.json({ error: 'Internal server error' }, { status: 500 }))
    const wrapped = withIamAccess(engine(), 'read', 'post', async () => new Response('ok'), {
      getUserId: boom,
      onError,
    })
    const res = await wrapped(new Request('https://example.com/post'), { params: {} })
    expect(res.status).toBe(500)
    expect(onError).toHaveBeenCalledOnce()
  })

  // Control: a `getUserId` that returns null is still a 401, not a 500.
  it('still answers 401 when getUserId returns null', async () => {
    const mw = expressMiddleware(engine(), { getUserId: () => null })
    const res = expressRes()
    await mw({ method: 'GET', path: '/post' } as Parameters<typeof mw>[0], res as Parameters<typeof mw>[1], vi.fn())
    expect(res.statusCode).toBe(401)
  })
})

// SECURITY: `env.ip` feeds `matches` conditions, so every IP source goes through the same caps.
describe('iamExtractEnvironment caps every IP source', () => {
  it('drops an oversized req.ip', () => {
    expect(iamExtractEnvironment({ ip: 'x'.repeat(100_000) }, { trustProxy: true }).ip).toBeUndefined()
  })

  it('takes the leftmost hop of a comma-joined req.ip', () => {
    expect(iamExtractEnvironment({ ip: '1.1.1.1, 2.2.2.2' }, { trustProxy: true }).ip).toBe('1.1.1.1')
  })

  // Control: an ordinary address still passes through untouched.
  it('keeps a normal req.ip', () => {
    expect(iamExtractEnvironment({ ip: '203.0.113.7' }, { trustProxy: true }).ip).toBe('203.0.113.7')
  })

  // Without `trustProxy` the ip is undefined on every integration, so IP rules cannot differ between them.
  it('reports no ip at all unless the app opts in', () => {
    expect(iamExtractEnvironment({ ip: '203.0.113.7' }).ip).toBeUndefined()
  })
})

// INFO: Nest's base filter maps a non-`HttpException` to a non-500 only when it has `statusCode` and `message`.
describe('nest admin gate throws an error Nest can map', () => {
  const ops = () => createIamAdminOperations(engine(), { authorize: () => false, csrfCheck: false })

  it('carries statusCode 401 as well as status', async () => {
    const err = await ops()
      .listPolicies({ method: 'GET' })
      .catch((e: unknown) => e)
    expect(err).toBeInstanceOf(Error)
    expect(err).toMatchObject({ message: 'Unauthorized', status: 401, statusCode: 401 })
  })

  it('carries statusCode 403 for a failed CSRF check', async () => {
    const withCsrf = createIamAdminOperations(engine(), { authorize: () => true, csrfCheck: () => false })
    const err = await withCsrf.listPolicies({ method: 'POST' }).catch((e: unknown) => e)
    expect(err).toMatchObject({ status: 403, statusCode: 403 })
  })

  // Control: an authorized call still resolves, so the two above do not pass because every call throws.
  it('resolves when authorize passes', async () => {
    const allowed = createIamAdminOperations(engine(), { authorize: () => true, csrfCheck: false })
    await expect(allowed.listPolicies({ method: 'GET' })).resolves.toBeDefined()
  })
})
