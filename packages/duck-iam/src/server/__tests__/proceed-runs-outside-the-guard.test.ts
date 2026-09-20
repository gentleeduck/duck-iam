import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../adapters/memory'
import { IamEngine } from '../../core/engine'
import { iamGuard as expressGuard, iamAccessMiddleware as expressMiddleware } from '../express'
import { iamAccessMiddleware as honoMiddleware } from '../hono'
import { withIamAccess } from '../next'

// Hono and Next both call the downstream handler outside their try, each with a comment saying why: a route's own
// error belongs to the framework, not to the authorization guard's `onError`. Express called `next()` inside it.

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

const routeBlewUp = () => {
  throw new Error('route blew up')
}

describe('an error from downstream is the framework’s, not the guard’s', () => {
  it('express middleware lets a route error through instead of answering 500 for it', async () => {
    const mw = expressMiddleware(engine(), { getUserId: () => 'u1' })
    const res = expressRes()

    await expect(
      mw({ method: 'GET', path: '/post' } as Parameters<typeof mw>[0], res as Parameters<typeof mw>[1], routeBlewUp),
    ).rejects.toThrow('route blew up')

    // Untouched: answering here would also bypass the app's own error middleware.
    expect({ body: res.body, statusCode: res.statusCode }).toEqual({ body: undefined, statusCode: 0 })
  })

  it('express guard does the same on its per-route path', async () => {
    const mw = expressGuard(engine(), 'read', 'post', { getUserId: () => 'u1' })
    const res = expressRes()

    await expect(
      mw(
        { method: 'GET', params: {}, path: '/post/1' } as Parameters<typeof mw>[0],
        res as Parameters<typeof mw>[1],
        routeBlewUp,
      ),
    ).rejects.toThrow('route blew up')

    expect(res.statusCode).toBe(0)
  })

  it('still routes its own failures to onError, which is what the try is for', async () => {
    const onError = vi.fn()
    const mw = expressMiddleware(engine(), {
      getUserId: () => {
        throw new Error('idp down')
      },
      onError,
    })
    const res = expressRes()

    await mw({ method: 'GET', path: '/post' } as Parameters<typeof mw>[0], res as Parameters<typeof mw>[1], vi.fn())

    expect(onError).toHaveBeenCalledTimes(1)
    expect(onError.mock.calls[0]?.[0]).toBeInstanceOf(Error)
  })

  it('still denies without calling next', async () => {
    const mw = expressMiddleware(engine(), { getUserId: () => 'u1' })
    const res = expressRes()
    const next = vi.fn()

    await mw({ method: 'DELETE', path: '/post' } as Parameters<typeof mw>[0], res as Parameters<typeof mw>[1], next)

    expect({ called: next.mock.calls.length, statusCode: res.statusCode }).toEqual({ called: 0, statusCode: 403 })
  })

  it('matches hono, which already had it outside the try', async () => {
    const mw = honoMiddleware(engine(), { getUserId: () => 'u1' })
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

    await expect(mw(ctx, routeBlewUp)).rejects.toThrow('route blew up')
  })

  it('matches next, which already had it outside the try', async () => {
    const handler = withIamAccess(engine(), 'read', 'post', routeBlewUp, { getUserId: () => 'u1' })

    await expect(handler(new Request('https://example.com/post'), { params: {} })).rejects.toThrow('route blew up')
  })
})
