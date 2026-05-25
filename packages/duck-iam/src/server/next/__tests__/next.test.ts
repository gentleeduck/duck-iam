import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { Engine } from '../../../core/engine'
import type { AccessControl } from '../../../core/types'
import { checkAccess, createAdminHandlers, createNextMiddleware, getPermissions, withAccess } from '../index'

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
    { action: 'update', resource: 'post' },
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

function makeRequest(opts: { url?: string; method?: string; headers?: Record<string, string> } = {}): Request {
  const url = opts.url ?? 'https://example.com/api/post'
  const init: RequestInit = { method: opts.method ?? 'GET' }
  if (opts.headers) init.headers = opts.headers
  return new Request(url, init)
}

describe('withAccess', () => {
  let engine: Engine<Action, ResourceType, RoleId, Scope>

  beforeEach(() => {
    engine = makeEngine()
  })

  it('returns 401 when getUserId returns null', async () => {
    const handler = vi.fn(async () => Response.json({ ok: true }))
    const wrapped = withAccess(engine, 'delete', 'post', handler, { getUserId: () => null })
    const res = await wrapped(makeRequest({ method: 'DELETE' }), { params: {} })
    expect(res.status).toBe(401)
    expect(handler).not.toHaveBeenCalled()
  })

  it('throws at construction when getUserId is omitted (SEC-101)', () => {
    const handler = vi.fn(async () => Response.json({ ok: true }))
    expect(() => withAccess(engine, 'delete', 'post', handler)).toThrow(/getUserId is required/)
  })

  it('returns 403 when not allowed', async () => {
    const handler = vi.fn(async () => Response.json({ ok: true }))
    const wrapped = withAccess(engine, 'delete', 'post', handler, { getUserId: () => 'user-viewer' })
    const res = await wrapped(makeRequest({ method: 'DELETE' }), { params: {} })
    expect(res.status).toBe(403)
    expect(handler).not.toHaveBeenCalled()
  })

  it('calls handler when allowed', async () => {
    const handler = vi.fn(async () => Response.json({ ok: true }))
    const wrapped = withAccess(engine, 'delete', 'post', handler, { getUserId: () => 'user-editor' })
    const res = await wrapped(makeRequest({ method: 'DELETE' }), { params: {} })
    expect(handler).toHaveBeenCalledOnce()
    expect(res.status).toBe(200)
  })

  it('awaits Promise params', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const handler = vi.fn(async () => Response.json({ ok: true }))
    const wrapped = withAccess(engine, 'delete', 'post', handler, { getUserId: () => 'u' })
    await wrapped(makeRequest({ method: 'DELETE' }), { params: Promise.resolve({ id: '99' }) })
    expect(can.mock.calls[0]?.[2]?.id).toBe('99')
    can.mockRestore()
  })

  it('passes scope option', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const handler = vi.fn(async () => Response.json({ ok: true }))
    const wrapped = withAccess<Action, ResourceType, RoleId, Scope>(engine, 'delete', 'post', handler, {
      getUserId: () => 'u',
      scope: 'org-1',
    })
    await wrapped(makeRequest({ method: 'DELETE' }), { params: {} })
    expect(can.mock.calls[0]?.[4]).toBe('org-1')
    can.mockRestore()
  })

  it('default getEnvironment reads x-forwarded-for + ua', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const handler = vi.fn(async () => Response.json({ ok: true }))
    const wrapped = withAccess(engine, 'read', 'post', handler, { getUserId: () => 'u' })
    await wrapped(makeRequest({ headers: { 'x-forwarded-for': '1.1.1.1', 'user-agent': 'curl' } }), { params: {} })
    expect(can.mock.calls[0]?.[3]?.ip).toBe('1.1.1.1')
    expect(can.mock.calls[0]?.[3]?.userAgent).toBe('curl')
    can.mockRestore()
  })

  it('onError on engine throw', async () => {
    vi.spyOn(engine, 'can').mockRejectedValue(new Error('boom'))
    const onError = vi.fn(() => Response.json({ err: true }, { status: 599 }))
    const handler = vi.fn(async () => Response.json({ ok: true }))
    const wrapped = withAccess(engine, 'read', 'post', handler, { getUserId: () => 'u', onError })
    const res = await wrapped(makeRequest(), { params: {} })
    expect(res.status).toBe(599)
    expect(onError).toHaveBeenCalledOnce()
  })

  it('async getUserId supported', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const handler = vi.fn(async () => Response.json({ ok: true }))
    const wrapped = withAccess(engine, 'read', 'post', handler, {
      getUserId: async () => 'async-user',
    })
    await wrapped(makeRequest(), { params: {} })
    expect(can.mock.calls[0]?.[0]).toBe('async-user')
    can.mockRestore()
  })
})

describe('checkAccess', () => {
  it('delegates to engine.can with attributes:{}', async () => {
    const engine = makeEngine()
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const result = await checkAccess(engine, 'user-1', 'read', 'post', 'res-id', 'org-1' as Scope)
    expect(result).toBe(true)
    expect(can).toHaveBeenCalledWith(
      'user-1',
      'read',
      { type: 'post', id: 'res-id', attributes: {} },
      undefined,
      'org-1',
    )
    can.mockRestore()
  })
})

describe('getPermissions', () => {
  it('delegates to engine.permissions', async () => {
    const engine = makeEngine()
    const map = await getPermissions(engine, 'user-viewer', [
      { action: 'read', resource: 'post' },
      { action: 'delete', resource: 'post' },
    ])
    expect(map['read:post']).toBe(true)
    expect(map['delete:post']).toBe(false)
  })
})

describe('createNextMiddleware', () => {
  let engine: Engine<Action, ResourceType, RoleId, Scope>

  beforeEach(() => {
    engine = makeEngine()
  })

  it('returns null when no rule matches', async () => {
    const mw = createNextMiddleware(engine, {
      rules: [{ pattern: '/admin', resource: 'post' }],
      getUserId: () => 'u',
    })
    const res = await mw(makeRequest({ url: 'https://x.com/public' }))
    expect(res).toBeNull()
  })

  it('returns 401 when user missing', async () => {
    const mw = createNextMiddleware(engine, {
      rules: [{ pattern: '/post', resource: 'post' }],
      getUserId: () => null,
    })
    const res = await mw(makeRequest({ url: 'https://x.com/post' }))
    expect(res?.status).toBe(401)
  })

  it('returns null (allow) when user is allowed', async () => {
    const mw = createNextMiddleware(engine, {
      rules: [{ pattern: '/post', resource: 'post', action: 'read' }],
      getUserId: () => 'user-viewer',
    })
    const res = await mw(makeRequest({ url: 'https://x.com/post' }))
    expect(res).toBeNull()
  })

  it('returns 403 when not allowed', async () => {
    const mw = createNextMiddleware(engine, {
      rules: [{ pattern: '/post', resource: 'post', action: 'delete' }],
      getUserId: () => 'user-viewer',
    })
    const res = await mw(makeRequest({ url: 'https://x.com/post', method: 'DELETE' }))
    expect(res?.status).toBe(403)
  })

  it('regex pattern works', async () => {
    const mw = createNextMiddleware(engine, {
      rules: [{ pattern: /^\/admin\/.*/, resource: 'post', action: 'delete' }],
      getUserId: () => 'user-editor',
    })
    expect(await mw(makeRequest({ url: 'https://x.com/admin/dashboard' }))).toBeNull()
    expect(await mw(makeRequest({ url: 'https://x.com/public' }))).toBeNull()
  })

  it('infers action from method when not set', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const mw = createNextMiddleware(engine, {
      rules: [{ pattern: '/post', resource: 'post' }],
      getUserId: () => 'u',
    })
    await mw(makeRequest({ url: 'https://x.com/post', method: 'DELETE' }))
    expect(can.mock.calls[0]?.[1]).toBe('delete')
    can.mockRestore()
  })

  it('passes scope from rule', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const mw = createNextMiddleware<Action, ResourceType, RoleId, Scope>(engine, {
      rules: [{ pattern: '/post', resource: 'post', action: 'read', scope: 'org-1' }],
      getUserId: () => 'u',
    })
    await mw(makeRequest({ url: 'https://x.com/post' }))
    expect(can.mock.calls[0]?.[4]).toBe('org-1')
    can.mockRestore()
  })

  it('onError invoked on engine throw', async () => {
    vi.spyOn(engine, 'can').mockRejectedValue(new Error('boom'))
    const onError = vi.fn(() => Response.json({ err: true }, { status: 599 }))
    const mw = createNextMiddleware(engine, {
      rules: [{ pattern: '/post', resource: 'post', action: 'read' }],
      getUserId: () => 'u',
      onError,
    })
    const res = await mw(makeRequest({ url: 'https://x.com/post' }))
    expect(res?.status).toBe(599)
  })
})

describe('createAdminHandlers onAdminMutation (SEC-010)', () => {
  const flushMicrotasks = () => new Promise((r) => setTimeout(r, 0))

  function makeAdminReq(opts: { method: string; url?: string; body?: unknown }): Request {
    const url = opts.url ?? 'https://example.com/api/admin/policies'
    const init: RequestInit = { method: opts.method }
    if (opts.body !== undefined) {
      init.headers = { 'content-type': 'application/json' }
      init.body = JSON.stringify(opts.body)
    }
    return new Request(url, init)
  }

  it('csrfCheck rejecting blocks mutation with 403, authorize never called (SEC-103)', async () => {
    const engine = makeEngine()
    let authorizeCalled = false
    let savedPolicy = false
    const origSave = engine.admin.savePolicy.bind(engine.admin)
    engine.admin.savePolicy = async (p) => {
      savedPolicy = true
      return origSave(p)
    }
    const h = createAdminHandlers(engine, {
      authorize: (() => {
        authorizeCalled = true
        return { id: 'admin-1' }
      }) as never,
      csrfCheck: (req) => (req as Request).headers.get('sec-fetch-site') !== 'cross-site',
    })
    const req = new Request('https://example.com/api/admin/policies', {
      method: 'PUT',
      headers: { 'content-type': 'application/json', 'sec-fetch-site': 'cross-site' },
      body: JSON.stringify({ id: 'p1', name: 'P', algorithm: 'deny-overrides', rules: [] }),
    })
    const res = await h.savePolicy(req, { params: {} })
    expect(res.status).toBe(403)
    expect(authorizeCalled).toBe(false)
    expect(savedPolicy).toBe(false)
  })

  it('savePolicy fires with action:replace, target:policy, success:true', async () => {
    const engine = makeEngine()
    const events: unknown[] = []
    const h = createAdminHandlers(engine, {
      authorize: (() => ({ id: 'admin-1' })) as never,
      onAdminMutation: (e) => {
        events.push(e)
      },
    })
    const res = await h.savePolicy(
      makeAdminReq({
        method: 'PUT',
        url: 'https://example.com/api/admin/policies',
        body: { id: 'p1', name: 'P', algorithm: 'deny-overrides', rules: [] },
      }),
      { params: {} },
    )
    await flushMicrotasks()
    expect(res.status).toBe(200)
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
    expect(ev.path).toBe('/api/admin/policies')
    expect(ev.actor).toEqual({ id: 'admin-1' })
  })

  it('fires with success:false and error message when handler throws', async () => {
    const engine = makeEngine()
    const events: unknown[] = []
    const original = engine.admin.savePolicy
    engine.admin.savePolicy = async () => {
      throw new Error('save-failed')
    }
    const h = createAdminHandlers(engine, {
      authorize: () => true,
      onAdminMutation: (e) => {
        events.push(e)
      },
    })
    const res = await h.savePolicy(makeAdminReq({ method: 'PUT', body: {} }), { params: {} })
    await flushMicrotasks()
    engine.admin.savePolicy = original
    expect(res.status).toBe(500)
    expect(events).toHaveLength(1)
    const ev = events[0] as { success: boolean; error?: string }
    expect(ev.success).toBe(false)
    // Default `event.error` is the class name, not `err.message`.
    expect(ev.error).toBe('Error')
  })

  it('does NOT fire on GET (read) handlers', async () => {
    const engine = makeEngine()
    const events: unknown[] = []
    const h = createAdminHandlers(engine, {
      authorize: () => true,
      onAdminMutation: (e) => {
        events.push(e)
      },
    })
    await h.listPolicies(makeAdminReq({ method: 'GET' }), { params: {} })
    await h.listRoles(makeAdminReq({ method: 'GET' }), { params: {} })
    await flushMicrotasks()
    expect(events).toHaveLength(0)
  })

  it('hook is fire-and-forget - a throwing hook does not affect the response', async () => {
    const engine = makeEngine()
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const h = createAdminHandlers(engine, {
      authorize: () => true,
      onAdminMutation: () => {
        throw new Error('hook-explode')
      },
    })
    const res = await h.savePolicy(
      makeAdminReq({
        method: 'PUT',
        body: { id: 'p2', name: 'P', algorithm: 'deny-overrides', rules: [] },
      }),
      { params: {} },
    )
    const body = (await res.json()) as { ok?: boolean }
    expect(res.status).toBe(200)
    expect(body.ok).toBe(true)
    expect(errSpy).toHaveBeenCalled()
    errSpy.mockRestore()
  })

  it('SEC-039: redactPath rewrites event.path before the hook is called', async () => {
    const engine = makeEngine()
    const events: Array<{ path: string }> = []
    const h = createAdminHandlers(engine, {
      authorize: () => true,
      onAdminMutation: (e) => {
        events.push(e)
      },
      redactPath: (p) => p.replace(/\/[^/]+$/, '/:id'),
    })
    await h.revokeRole(
      makeAdminReq({ method: 'DELETE', url: 'https://example.com/subjects/user-secret-42/roles/role-tenant-acme' }),
      { params: { id: 'user-secret-42', roleId: 'role-tenant-acme' } },
    )
    await flushMicrotasks()
    expect(events).toHaveLength(1)
    expect(events[0]!.path).toBe('/subjects/user-secret-42/roles/:id')
    expect(events[0]!.path).not.toMatch(/role-tenant-acme/)
  })

  it('SEC-040: onAuditHookError receives thrown error and event', async () => {
    const engine = makeEngine()
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const captured: Array<{ err: unknown; event: { action: string; target: string } }> = []
    const boom = new Error('hook-boom')
    const h = createAdminHandlers(engine, {
      authorize: () => true,
      onAdminMutation: () => {
        throw boom
      },
      onAuditHookError: (err, event) => {
        captured.push({ err, event })
      },
    })
    await h.savePolicy(
      makeAdminReq({
        method: 'PUT',
        body: { id: 'p3', name: 'P', algorithm: 'deny-overrides', rules: [] },
      }),
      { params: {} },
    )
    await flushMicrotasks()
    expect(captured).toHaveLength(1)
    expect(captured[0]!.err).toBe(boom)
    expect(captured[0]!.event.action).toBe('replace')
    expect(captured[0]!.event.target).toBe('policy')
    expect(errSpy).not.toHaveBeenCalled()
    errSpy.mockRestore()
  })

  it('SEC-041: event.error defaults to the error class name', async () => {
    const engine = makeEngine()
    const events: Array<{ success: boolean; error?: string }> = []
    class PolicyValidationError extends Error {
      constructor() {
        super('SELECT * FROM pg_users WHERE password = ...')
      }
    }
    const original = engine.admin.savePolicy
    engine.admin.savePolicy = async () => {
      throw new PolicyValidationError()
    }
    const h = createAdminHandlers(engine, {
      authorize: () => true,
      onAdminMutation: (e) => {
        events.push(e)
      },
    })
    await h.savePolicy(makeAdminReq({ method: 'PUT', body: {} }), { params: {} })
    await flushMicrotasks()
    engine.admin.savePolicy = original
    expect(events).toHaveLength(1)
    expect(events[0]!.error).toBe('PolicyValidationError')
    expect(events[0]!.error).not.toMatch(/password/)
  })

  it('SEC-041: includeErrorMessage:true restores err.message', async () => {
    const engine = makeEngine()
    const events: Array<{ error?: string }> = []
    const original = engine.admin.savePolicy
    engine.admin.savePolicy = async () => {
      throw new Error('full-detailed-message')
    }
    const h = createAdminHandlers(engine, {
      authorize: () => true,
      includeErrorMessage: true,
      onAdminMutation: (e) => {
        events.push(e)
      },
    })
    await h.savePolicy(makeAdminReq({ method: 'PUT', body: {} }), { params: {} })
    await flushMicrotasks()
    engine.admin.savePolicy = original
    expect(events[0]!.error).toBe('full-detailed-message')
  })
})
