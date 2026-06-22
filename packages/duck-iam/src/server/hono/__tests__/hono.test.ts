import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../../core/engine'
import type { IamAccessControl } from '../../../core/types'
import { iamAccessMiddleware, iamBindAdminRouter, iamGuard } from '../index'

type Action = 'read' | 'create' | 'update' | 'delete'
type ResourceType = 'post' | 'comment'
type RoleId = 'viewer' | 'editor'
type Scope = 'org-1'

const viewerRole: IamAccessControl.IRole<Action, ResourceType, RoleId, Scope> = {
  id: 'viewer',
  name: 'Viewer',
  permissions: [{ action: 'read', resource: 'post' }],
}
const editorRole: IamAccessControl.IRole<Action, ResourceType, RoleId, Scope> = {
  id: 'editor',
  name: 'Editor',
  inherits: ['viewer'],
  permissions: [
    { action: 'create', resource: 'post' },
    { action: 'delete', resource: 'post' },
  ],
}

function makeEngine() {
  const adapter = new IamMemoryAdapter<Action, ResourceType, RoleId, Scope>({
    roles: [viewerRole, editorRole],
    assignments: { 'user-viewer': ['viewer'], 'user-editor': ['editor'] },
  })
  return new IamEngine<Action, ResourceType, RoleId, Scope>({ adapter, cacheTTL: 0 })
}

interface RecordedJson {
  data: unknown
  status: number
}

function makeContext(opts: {
  method?: string
  path?: string
  url?: string
  headers?: Record<string, string>
  state?: Record<string, unknown>
  params?: Record<string, string>
}) {
  const json: RecordedJson[] = []
  const state = opts.state ?? {}
  return {
    json,
    ctx: {
      req: {
        method: opts.method ?? 'GET',
        path: opts.path ?? '/',
        url: opts.url ?? `https://example.com${opts.path ?? '/'}`,
        header(name: string) {
          return opts.headers?.[name.toLowerCase()] ?? opts.headers?.[name]
        },
        param(name: string) {
          return opts.params?.[name]
        },
      },
      get(key: string) {
        return state[key]
      },
      set(key: string, value: unknown) {
        state[key] = value
      },
      json(data: unknown, status = 200) {
        json.push({ data, status })
        return new Response(JSON.stringify(data), { status })
      },
      text(_data: string, status = 200) {
        return new Response(_data, { status })
      },
    },
  }
}

describe('iamAccessMiddleware (hono)', () => {
  let engine: IamEngine<Action, ResourceType, RoleId, Scope>

  beforeEach(() => {
    engine = makeEngine()
  })

  it('returns 401 when userId missing', async () => {
    const mw = iamAccessMiddleware(engine)
    const { ctx, json } = makeContext({ method: 'GET', path: '/post' })
    const next = vi.fn(async () => undefined)
    await mw(ctx, next)
    expect(json[0]?.status).toBe(401)
    expect(next).not.toHaveBeenCalled()
  })

  it('reads userId from context state first', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const mw = iamAccessMiddleware(engine)
    const { ctx } = makeContext({ method: 'GET', path: '/post', state: { userId: 'user-state' } })
    await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    expect(can.mock.calls[0]?.[0]).toBe('user-state')
    can.mockRestore()
  })

  it('does NOT default to spoofable x-user-id header', async () => {
    const mw = iamAccessMiddleware(engine)
    const { ctx } = makeContext({ method: 'GET', path: '/post', headers: { 'x-user-id': 'spoofed-admin' } })
    const res = await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    // No `c.set('userId', ...)` was called upstream, so default getUserId
    // returns null and middleware fails closed at 401.
    expect(res?.status).toBe(401)
  })

  it('honours c.set(userId) from upstream auth middleware', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const mw = iamAccessMiddleware(engine)
    const { ctx } = makeContext({ method: 'GET', path: '/post' })
    ctx.set('userId', 'trusted-user')
    await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    expect(can.mock.calls[0]?.[0]).toBe('trusted-user')
    can.mockRestore()
  })

  it('calls next when allowed', async () => {
    const mw = iamAccessMiddleware(engine, { getUserId: () => 'user-viewer' })
    const { ctx } = makeContext({ method: 'GET', path: '/post' })
    const next = vi.fn(async () => undefined)
    await mw(ctx, next)
    expect(next).toHaveBeenCalledOnce()
  })

  it('returns 403 default when denied', async () => {
    const mw = iamAccessMiddleware(engine, { getUserId: () => 'user-viewer' })
    const { ctx, json } = makeContext({ method: 'DELETE', path: '/post' })
    await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    expect(json[0]?.status).toBe(403)
  })

  it('infers action from method', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const mw = iamAccessMiddleware(engine, { getUserId: () => 'u' })
    const { ctx } = makeContext({ method: 'PATCH', path: '/post' })
    await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    expect(can.mock.calls[0]?.[1]).toBe('update')
    can.mockRestore()
  })

  it('uses default env extractor with cf-connecting-ip', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const mw = iamAccessMiddleware(engine, { getUserId: () => 'u' })
    const { ctx } = makeContext({
      method: 'GET',
      path: '/post',
      headers: { 'cf-connecting-ip': '1.2.3.4', 'user-agent': 'curl' },
    })
    await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    expect(can.mock.calls[0]?.[3]?.ip).toBe('1.2.3.4')
    expect(can.mock.calls[0]?.[3]?.userAgent).toBe('curl')
    can.mockRestore()
  })

  it('falls back to x-forwarded-for', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const mw = iamAccessMiddleware(engine, { getUserId: () => 'u' })
    const { ctx } = makeContext({
      method: 'GET',
      path: '/post',
      headers: { 'x-forwarded-for': '5.6.7.8' },
    })
    await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    expect(can.mock.calls[0]?.[3]?.ip).toBe('5.6.7.8')
    can.mockRestore()
  })

  it('onError handles engine throw', async () => {
    vi.spyOn(engine, 'can').mockRejectedValue(new Error('boom'))
    const onError = vi.fn((_e, c) => c.json({ err: true }, 599))
    const mw = iamAccessMiddleware(engine, { getUserId: () => 'u', onError })
    const { ctx, json } = makeContext({ method: 'GET', path: '/post' })
    await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    expect(json[0]?.status).toBe(599)
    expect(onError).toHaveBeenCalledOnce()
  })

  it('getScope passed to engine', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const mw = iamAccessMiddleware<Action, ResourceType, RoleId, Scope>(engine, {
      getUserId: () => 'u',
      getScope: () => 'org-1',
    })
    const { ctx } = makeContext({ method: 'GET', path: '/post' })
    await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    expect(can.mock.calls[0]?.[4]).toBe('org-1')
    can.mockRestore()
  })
})

describe('iamGuard (hono)', () => {
  let engine: IamEngine<Action, ResourceType, RoleId, Scope>

  beforeEach(() => {
    engine = makeEngine()
  })

  it('401 when no user', async () => {
    const mw = iamGuard(engine, 'delete', 'post')
    const { ctx, json } = makeContext({ method: 'DELETE', path: '/post/1' })
    await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    expect(json[0]?.status).toBe(401)
  })

  it('next() when allowed', async () => {
    const mw = iamGuard(engine, 'delete', 'post', { getUserId: () => 'user-editor' })
    const { ctx } = makeContext({ method: 'DELETE', path: '/post/1', params: { id: '1' } })
    const next = vi.fn(async () => undefined)
    await mw(ctx, next)
    expect(next).toHaveBeenCalledOnce()
  })

  it('403 when denied', async () => {
    const mw = iamGuard(engine, 'delete', 'post', { getUserId: () => 'user-viewer' })
    const { ctx, json } = makeContext({ method: 'DELETE', path: '/post/1', params: { id: '1' } })
    await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    expect(json[0]?.status).toBe(403)
  })

  it('passes resource id from param("id")', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const mw = iamGuard(engine, 'delete', 'post', { getUserId: () => 'u' })
    const { ctx } = makeContext({ method: 'DELETE', path: '/post/42', params: { id: '42' } })
    await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    expect(can.mock.calls[0]?.[2]?.id).toBe('42')
    can.mockRestore()
  })

  it('onError invoked on throw', async () => {
    vi.spyOn(engine, 'can').mockRejectedValue(new Error('boom'))
    const onError = vi.fn((_e, c) => c.json({ err: true }, 599))
    const mw = iamGuard(engine, 'delete', 'post', { getUserId: () => 'u', onError })
    const { ctx, json } = makeContext({ method: 'DELETE', path: '/post/1' })
    await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    expect(json[0]?.status).toBe(599)
  })
})

describe('iamBindAdminRouter (hono)', () => {
  it('refuses construction without an authorize callback', () => {
    const engine = makeEngine()
    const fakeRouter = { get: vi.fn(), put: vi.fn(), post: vi.fn(), delete: vi.fn() }
    expect(() => iamBindAdminRouter(fakeRouter, engine, undefined as never)).toThrow(/authorize/)
  })

  it('gates handlers behind authorize and dispatches when allowed', async () => {
    const engine = makeEngine()
    type Handler = (c: unknown) => Promise<Response> | Response
    const handlers: Record<string, Handler> = {}
    const router = {
      get: vi.fn((path: string, h: Handler) => {
        handlers[`GET ${path}`] = h
      }),
      put: vi.fn((path: string, h: Handler) => {
        handlers[`PUT ${path}`] = h
      }),
      post: vi.fn((path: string, h: Handler) => {
        handlers[`POST ${path}`] = h
      }),
      delete: vi.fn((path: string, h: Handler) => {
        handlers[`DELETE ${path}`] = h
      }),
    }
    iamBindAdminRouter(router, engine, { authorize: () => true })

    const ctxAllow = {
      req: { param: () => undefined, json: async () => [] },
      json: (data: unknown, status?: number) => ({ data, status: status ?? 200 }) as unknown as Response,
    }
    const res = (await handlers['GET /policies']!(ctxAllow)) as unknown as { status: number }
    expect(res.status).toBe(200)
  })

  it('returns 401 when authorize rejects', async () => {
    const engine = makeEngine()
    type Handler = (c: unknown) => Promise<Response> | Response
    const handlers: Record<string, Handler> = {}
    const router = {
      get: vi.fn((path: string, h: Handler) => {
        handlers[`GET ${path}`] = h
      }),
      put: vi.fn(),
      post: vi.fn(),
      delete: vi.fn(),
    }
    iamBindAdminRouter(router, engine, { authorize: () => false })
    const ctxDeny = {
      req: { param: () => undefined, json: async () => ({}) },
      json: (data: unknown, status?: number) => ({ data, status: status ?? 200 }) as unknown as Response,
    }
    const res = (await handlers['GET /policies']!(ctxDeny)) as unknown as { status: number; data: unknown }
    expect(res.status).toBe(401)
    expect((res.data as { error: string }).error).toBe('Unauthorized')
  })

  it('csrfCheck rejecting blocks mutation with 403, authorize never called', async () => {
    const engine = makeEngine()
    let authorizeCalled = false
    type Handler = (c: unknown) => Promise<Response> | Response
    const handlers: Record<string, Handler> = {}
    const router = {
      get: vi.fn(),
      put: vi.fn((path: string, h: Handler) => {
        handlers[`PUT ${path}`] = h
      }),
      post: vi.fn(),
      delete: vi.fn(),
    }
    iamBindAdminRouter(router, engine, {
      authorize: () => {
        authorizeCalled = true
        return true
      },
      csrfCheck: (c) =>
        (c as { req: { header: (n: string) => string | undefined } }).req.header('sec-fetch-site') !== 'cross-site',
    })
    const ctx = {
      req: {
        param: () => undefined,
        json: async () => ({ id: 'p1', name: 'P', algorithm: 'deny-overrides', rules: [] }),
        header: (n: string) => (n === 'sec-fetch-site' ? 'cross-site' : undefined),
      },
      json: (data: unknown, status?: number) => ({ data, status: status ?? 200 }) as unknown as Response,
    }
    const res = (await handlers['PUT /policies']!(ctx)) as unknown as { status: number; data: unknown }
    expect(res.status).toBe(403)
    expect(authorizeCalled).toBe(false)
  })

  describe('onAdminMutation', () => {
    const flushMicrotasks = () => new Promise((r) => setTimeout(r, 0))

    type Handler = (c: unknown) => Promise<Response> | Response

    const makeRouterRec = () => {
      const handlers: Record<string, Handler> = {}
      const record = (key: string) => (path: string, h: Handler) => {
        handlers[`${key} ${path}`] = h
      }
      return {
        handlers,
        router: {
          get: vi.fn(record('GET')),
          put: vi.fn(record('PUT')),
          post: vi.fn(record('POST')),
          delete: vi.fn(record('DELETE')),
        },
      }
    }

    const makeMutCtx = (opts: { method: string; path: string; body?: unknown; paramId?: string }) => ({
      req: {
        method: opts.method,
        path: opts.path,
        param: (name: string) => (name === 'id' ? opts.paramId : undefined),
        json: async () => opts.body ?? {},
      },
      json: (data: unknown, status?: number) => ({ data, status: status ?? 200 }) as unknown as Response,
    })

    it('fires on PUT /policies with action:replace, target:policy, success:true', async () => {
      const engine = makeEngine()
      const { router, handlers } = makeRouterRec()
      const events: unknown[] = []
      iamBindAdminRouter(router, engine, {
        authorize: (() => ({ id: 'admin-1' })) as never,
        onAdminMutation: (e) => {
          events.push(e)
        },
      })
      await handlers['PUT /policies']!(
        makeMutCtx({
          method: 'PUT',
          path: '/policies',
          body: { id: 'p1', name: 'P', algorithm: 'deny-overrides', rules: [] },
        }),
      )
      await flushMicrotasks()
      expect(events).toHaveLength(1)
      const ev = events[0] as {
        action: string
        target: string
        success: boolean
        method: string
        path: string
        actor: unknown
      }
      expect(ev.action).toBe('replace')
      expect(ev.target).toBe('policy')
      expect(ev.success).toBe(true)
      expect(ev.method).toBe('PUT')
      expect(ev.path).toBe('/policies')
      expect(ev.actor).toEqual({ id: 'admin-1' })
    })

    it('fires with success:false and error message when handler throws', async () => {
      const engine = makeEngine()
      const { router, handlers } = makeRouterRec()
      const events: unknown[] = []
      iamBindAdminRouter(router, engine, {
        authorize: () => true,
        onAdminMutation: (e) => {
          events.push(e)
        },
      })
      const original = engine.admin.savePolicy
      engine.admin.savePolicy = async () => {
        throw new Error('save-failed')
      }
      await handlers['PUT /policies']!(makeMutCtx({ method: 'PUT', path: '/policies', body: {} }))
      await flushMicrotasks()
      engine.admin.savePolicy = original
      expect(events).toHaveLength(1)
      const ev = events[0] as { success: boolean; error?: string }
      expect(ev.success).toBe(false)
      // Default `event.error` is the class name, not `err.message`.
      expect(ev.error).toBe('Error')
    })

    it('does NOT fire on GET (read) requests', async () => {
      const engine = makeEngine()
      const { router, handlers } = makeRouterRec()
      const events: unknown[] = []
      iamBindAdminRouter(router, engine, {
        authorize: () => true,
        onAdminMutation: (e) => {
          events.push(e)
        },
      })
      await handlers['GET /policies']!(makeMutCtx({ method: 'GET', path: '/policies' }))
      await handlers['GET /roles']!(makeMutCtx({ method: 'GET', path: '/roles' }))
      await flushMicrotasks()
      expect(events).toHaveLength(0)
    })

    it('hook is fire-and-forget - a throwing hook does not affect the response', async () => {
      const engine = makeEngine()
      const { router, handlers } = makeRouterRec()
      const errSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
      iamBindAdminRouter(router, engine, {
        authorize: () => true,
        onAdminMutation: () => {
          throw new Error('hook-explode')
        },
      })
      const res = (await handlers['PUT /policies']!(
        makeMutCtx({
          method: 'PUT',
          path: '/policies',
          body: { id: 'p2', name: 'P', algorithm: 'deny-overrides', rules: [] },
        }),
      )) as unknown as { status: number; data: { ok?: boolean } }
      expect(res.status).toBe(200)
      expect(res.data.ok).toBe(true)
      expect(errSpy).toHaveBeenCalled()
      errSpy.mockRestore()
    })

    it('redactPath rewrites event.path before the hook is called', async () => {
      const engine = makeEngine()
      const { router, handlers } = makeRouterRec()
      const events: Array<{ path: string }> = []
      iamBindAdminRouter(router, engine, {
        authorize: () => true,
        onAdminMutation: (e) => {
          events.push(e)
        },
        redactPath: (p) => p.replace(/\/[^/]+$/, '/:id'),
      })
      await handlers['DELETE /subjects/:id/roles/:roleId']!(
        makeMutCtx({
          method: 'DELETE',
          path: '/subjects/user-secret-42/roles/role-tenant-acme',
          paramId: 'user-secret-42',
        }),
      )
      await flushMicrotasks()
      expect(events).toHaveLength(1)
      expect(events[0]!.path).toBe('/subjects/user-secret-42/roles/:id')
      expect(events[0]!.path).not.toMatch(/role-tenant-acme/)
    })

    it('onAuditHookError receives thrown error and event', async () => {
      const engine = makeEngine()
      const { router, handlers } = makeRouterRec()
      const errSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
      const captured: Array<{ err: unknown; event: { action: string; target: string } }> = []
      const boom = new Error('hook-boom')
      iamBindAdminRouter(router, engine, {
        authorize: () => true,
        onAdminMutation: () => {
          throw boom
        },
        onAuditHookError: (err, event) => {
          captured.push({ err, event })
        },
      })
      await handlers['PUT /policies']!(
        makeMutCtx({
          method: 'PUT',
          path: '/policies',
          body: { id: 'p3', name: 'P', algorithm: 'deny-overrides', rules: [] },
        }),
      )
      await flushMicrotasks()
      expect(captured).toHaveLength(1)
      expect(captured[0]!.err).toBe(boom)
      expect(captured[0]!.event.action).toBe('replace')
      expect(captured[0]!.event.target).toBe('policy')
      expect(errSpy).not.toHaveBeenCalled()
      errSpy.mockRestore()
    })

    it('event.error defaults to the error class name, not err.message', async () => {
      const engine = makeEngine()
      const { router, handlers } = makeRouterRec()
      const events: Array<{ success: boolean; error?: string }> = []
      iamBindAdminRouter(router, engine, {
        authorize: () => true,
        onAdminMutation: (e) => {
          events.push(e)
        },
      })
      class PolicyValidationError extends Error {
        constructor() {
          super('SELECT * FROM pg_users WHERE password = ...')
        }
      }
      const original = engine.admin.savePolicy
      engine.admin.savePolicy = async () => {
        throw new PolicyValidationError()
      }
      await handlers['PUT /policies']!(makeMutCtx({ method: 'PUT', path: '/policies', body: {} }))
      await flushMicrotasks()
      engine.admin.savePolicy = original
      expect(events).toHaveLength(1)
      expect(events[0]!.success).toBe(false)
      expect(events[0]!.error).toBe('PolicyValidationError')
      expect(events[0]!.error).not.toMatch(/password/)
    })

    it('includeErrorMessage:true restores err.message', async () => {
      const engine = makeEngine()
      const { router, handlers } = makeRouterRec()
      const events: Array<{ error?: string }> = []
      iamBindAdminRouter(router, engine, {
        authorize: () => true,
        includeErrorMessage: true,
        onAdminMutation: (e) => {
          events.push(e)
        },
      })
      const original = engine.admin.savePolicy
      engine.admin.savePolicy = async () => {
        throw new Error('full-detailed-message')
      }
      await handlers['PUT /policies']!(makeMutCtx({ method: 'PUT', path: '/policies', body: {} }))
      await flushMicrotasks()
      engine.admin.savePolicy = original
      expect(events[0]!.error).toBe('full-detailed-message')
    })
  })
})
