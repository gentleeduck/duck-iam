import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { Engine } from '../../../core/engine'
import type { AccessControl } from '../../../core/types'
import { accessMiddleware, bindAdminRouter, guard } from '../index'

type Action = 'read' | 'create' | 'update' | 'delete'
type ResourceType = 'post' | 'comment'
type RoleId = 'viewer' | 'editor'
type Scope = 'org-1'

const viewerRole: AccessControl.IRole<Action, ResourceType, RoleId, Scope> = {
  id: 'viewer',
  name: 'Viewer',
  permissions: [{ action: 'read', resource: 'post' }],
}
const editorRole: AccessControl.IRole<Action, ResourceType, RoleId, Scope> = {
  id: 'editor',
  name: 'Editor',
  inherits: ['viewer'],
  permissions: [
    { action: 'create', resource: 'post' },
    { action: 'delete', resource: 'post' },
  ],
}

function makeEngine() {
  const adapter = new MemoryAdapter<Action, ResourceType, RoleId, Scope>({
    roles: [viewerRole, editorRole],
    assignments: { 'user-viewer': ['viewer'], 'user-editor': ['editor'] },
  })
  return new Engine<Action, ResourceType, RoleId, Scope>({ adapter, cacheTTL: 0 })
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

describe('accessMiddleware (hono)', () => {
  let engine: Engine<Action, ResourceType, RoleId, Scope>

  beforeEach(() => {
    engine = makeEngine()
  })

  it('returns 401 when userId missing', async () => {
    const mw = accessMiddleware(engine)
    const { ctx, json } = makeContext({ method: 'GET', path: '/post' })
    const next = vi.fn(async () => undefined)
    await mw(ctx, next)
    expect(json[0]?.status).toBe(401)
    expect(next).not.toHaveBeenCalled()
  })

  it('reads userId from context state first', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const mw = accessMiddleware(engine)
    const { ctx } = makeContext({ method: 'GET', path: '/post', state: { userId: 'user-state' } })
    await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    expect(can.mock.calls[0]?.[0]).toBe('user-state')
    can.mockRestore()
  })

  it('falls back to x-user-id header', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const mw = accessMiddleware(engine)
    const { ctx } = makeContext({ method: 'GET', path: '/post', headers: { 'x-user-id': 'user-hdr' } })
    await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    expect(can.mock.calls[0]?.[0]).toBe('user-hdr')
    can.mockRestore()
  })

  it('calls next when allowed', async () => {
    const mw = accessMiddleware(engine, { getUserId: () => 'user-viewer' })
    const { ctx } = makeContext({ method: 'GET', path: '/post' })
    const next = vi.fn(async () => undefined)
    await mw(ctx, next)
    expect(next).toHaveBeenCalledOnce()
  })

  it('returns 403 default when denied', async () => {
    const mw = accessMiddleware(engine, { getUserId: () => 'user-viewer' })
    const { ctx, json } = makeContext({ method: 'DELETE', path: '/post' })
    await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    expect(json[0]?.status).toBe(403)
  })

  it('infers action from method', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const mw = accessMiddleware(engine, { getUserId: () => 'u' })
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
    const mw = accessMiddleware(engine, { getUserId: () => 'u' })
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
    const mw = accessMiddleware(engine, { getUserId: () => 'u' })
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
    const mw = accessMiddleware(engine, { getUserId: () => 'u', onError })
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
    const mw = accessMiddleware<Action, ResourceType, RoleId, Scope>(engine, {
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

describe('guard (hono)', () => {
  let engine: Engine<Action, ResourceType, RoleId, Scope>

  beforeEach(() => {
    engine = makeEngine()
  })

  it('401 when no user', async () => {
    const mw = guard(engine, 'delete', 'post')
    const { ctx, json } = makeContext({ method: 'DELETE', path: '/post/1' })
    await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    expect(json[0]?.status).toBe(401)
  })

  it('next() when allowed', async () => {
    const mw = guard(engine, 'delete', 'post', { getUserId: () => 'user-editor' })
    const { ctx } = makeContext({ method: 'DELETE', path: '/post/1', params: { id: '1' } })
    const next = vi.fn(async () => undefined)
    await mw(ctx, next)
    expect(next).toHaveBeenCalledOnce()
  })

  it('403 when denied', async () => {
    const mw = guard(engine, 'delete', 'post', { getUserId: () => 'user-viewer' })
    const { ctx, json } = makeContext({ method: 'DELETE', path: '/post/1', params: { id: '1' } })
    await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    expect(json[0]?.status).toBe(403)
  })

  it('passes resource id from param("id")', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const mw = guard(engine, 'delete', 'post', { getUserId: () => 'u' })
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
    const mw = guard(engine, 'delete', 'post', { getUserId: () => 'u', onError })
    const { ctx, json } = makeContext({ method: 'DELETE', path: '/post/1' })
    await mw(
      ctx,
      vi.fn(async () => undefined),
    )
    expect(json[0]?.status).toBe(599)
  })
})

describe('bindAdminRouter (hono)', () => {
  it('refuses construction without an authorize callback', () => {
    const engine = makeEngine()
    const fakeRouter = { get: vi.fn(), put: vi.fn(), post: vi.fn(), delete: vi.fn() }
    expect(() => bindAdminRouter(fakeRouter, engine, undefined as never)).toThrow(/authorize/)
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
    bindAdminRouter(router, engine, { authorize: () => true })

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
    bindAdminRouter(router, engine, { authorize: () => false })
    const ctxDeny = {
      req: { param: () => undefined, json: async () => ({}) },
      json: (data: unknown, status?: number) => ({ data, status: status ?? 200 }) as unknown as Response,
    }
    const res = (await handlers['GET /policies']!(ctxDeny)) as unknown as { status: number; data: unknown }
    expect(res.status).toBe(401)
    expect((res.data as { error: string }).error).toBe('Unauthorized')
  })

  // SEC-010: admin mutation audit hook.
  describe('onAdminMutation (SEC-010)', () => {
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
      bindAdminRouter(router, engine, {
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
      bindAdminRouter(router, engine, {
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
      expect(ev.error).toBe('save-failed')
    })

    it('does NOT fire on GET (read) requests', async () => {
      const engine = makeEngine()
      const { router, handlers } = makeRouterRec()
      const events: unknown[] = []
      bindAdminRouter(router, engine, {
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

    it('hook is fire-and-forget — a throwing hook does not affect the response', async () => {
      const engine = makeEngine()
      const { router, handlers } = makeRouterRec()
      const errSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
      bindAdminRouter(router, engine, {
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
  })
})
