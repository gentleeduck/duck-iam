import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../../core/engine'
import type { AccessControl } from '../../../core/types'
import {
  createIamAdminOperations,
  createIamEngineProvider,
  IAM_ACCESS_ENGINE_TOKEN,
  IAM_ACCESS_METADATA_KEY,
  IamAuthorize,
  iamNestAccessGuard,
} from '../index'

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
  const adapter = new IamMemoryAdapter<Action, ResourceType, RoleId, Scope>({
    roles: [viewerRole, editorRole],
    assignments: { 'user-viewer': ['viewer'], 'user-editor': ['editor'] },
  })
  return new IamEngine<Action, ResourceType, RoleId, Scope>({ adapter, cacheTTL: 0 })
}

function makeCtx(opts: {
  user?: Record<string, unknown>
  params?: Record<string, string>
  method?: string
  path?: string
  routePath?: string
  headers?: Record<string, string>
  handler: object
}) {
  return {
    switchToHttp() {
      return {
        getRequest() {
          return {
            user: opts.user,
            params: opts.params ?? {},
            method: opts.method ?? 'GET',
            path: opts.path ?? '/',
            route: opts.routePath ? { path: opts.routePath } : undefined,
            headers: opts.headers,
          }
        },
      }
    },
    getHandler() {
      return opts.handler
    },
  }
}

describe('@IamAuthorize decorator', () => {
  it('attaches __accessMeta to descriptor.value', () => {
    const fn = function handler() {
      return null
    }
    const desc = { value: fn, configurable: true, writable: true } as PropertyDescriptor
    const dec = IamAuthorize({ action: 'delete', resource: 'post' })
    dec({} as never, 'method', desc)
    expect((fn as unknown as { __accessMeta: { action: string } }).__accessMeta).toEqual({
      action: 'delete',
      resource: 'post',
    })
  })

  it('default meta has infer:true', () => {
    const fn = function handler() {
      return null
    }
    const desc = { value: fn, configurable: true, writable: true } as PropertyDescriptor
    IamAuthorize()({} as never, 'method', desc)
    expect((fn as unknown as { __accessMeta: { infer: boolean } }).__accessMeta.infer).toBe(true)
  })

  it('exports stable metadata key', () => {
    expect(IAM_ACCESS_METADATA_KEY).toBe('duck-iam:authorize')
  })
})

describe('iamNestAccessGuard', () => {
  let engine: IamEngine<Action, ResourceType, RoleId, Scope>

  beforeEach(() => {
    engine = makeEngine()
  })

  it('returns true when handler has no @IamAuthorize meta', async () => {
    const guard = iamNestAccessGuard(engine)
    const handler = function noauth() {}
    const ctx = makeCtx({ user: { id: 'user-viewer' }, handler })
    expect(await guard(ctx)).toBe(true)
  })

  it('returns false when no userId resolved', async () => {
    const guard = iamNestAccessGuard(engine)
    const handler = function h() {}
    Object.defineProperty(handler, '__accessMeta', {
      value: { action: 'delete', resource: 'post' },
    })
    const ctx = makeCtx({ handler })
    expect(await guard(ctx)).toBe(false)
  })

  it('returns true when allowed', async () => {
    const guard = iamNestAccessGuard(engine)
    const handler = function h() {}
    Object.defineProperty(handler, '__accessMeta', {
      value: { action: 'delete', resource: 'post' },
    })
    const ctx = makeCtx({ user: { id: 'user-editor' }, handler })
    expect(await guard(ctx)).toBe(true)
  })

  it('returns false when denied', async () => {
    const guard = iamNestAccessGuard(engine)
    const handler = function h() {}
    Object.defineProperty(handler, '__accessMeta', {
      value: { action: 'delete', resource: 'post' },
    })
    const ctx = makeCtx({ user: { id: 'user-viewer' }, handler })
    expect(await guard(ctx)).toBe(false)
  })

  it('uses user.sub fallback when user.id missing', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const guard = iamNestAccessGuard(engine)
    const handler = function h() {}
    Object.defineProperty(handler, '__accessMeta', {
      value: { action: 'read', resource: 'post' },
    })
    const ctx = makeCtx({ user: { sub: 'user-from-sub' }, handler })
    await guard(ctx)
    expect(can.mock.calls[0]?.[0]).toBe('user-from-sub')
    can.mockRestore()
  })

  it('uses params.id as resource id', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const guard = iamNestAccessGuard(engine)
    const handler = function h() {}
    Object.defineProperty(handler, '__accessMeta', {
      value: { action: 'delete', resource: 'post' },
    })
    const ctx = makeCtx({ user: { id: 'u' }, params: { id: '42' }, handler })
    await guard(ctx)
    expect(can.mock.calls[0]?.[2]?.id).toBe('42')
    can.mockRestore()
  })

  it('infer:true derives action from method and resource from path', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const guard = iamNestAccessGuard(engine)
    const handler = function h() {}
    Object.defineProperty(handler, '__accessMeta', { value: { infer: true } })
    const ctx = makeCtx({
      user: { id: 'u' },
      method: 'DELETE',
      routePath: '/api/posts/:id',
      handler,
    })
    await guard(ctx)
    expect(can.mock.calls[0]?.[1]).toBe('delete')
    can.mockRestore()
  })

  it('decorator scope takes precedence over getScope', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const guard = iamNestAccessGuard<Action, ResourceType, RoleId, Scope>(engine, {
      getScope: () => 'org-1',
    })
    const handler = function h() {}
    Object.defineProperty(handler, '__accessMeta', {
      value: { action: 'delete', resource: 'post', scope: 'org-decorator' },
    })
    const ctx = makeCtx({ user: { id: 'u' }, handler })
    await guard(ctx)
    expect(can.mock.calls[0]?.[4]).toBe('org-decorator')
    can.mockRestore()
  })

  it('falls back to getScope when decorator scope absent', async () => {
    const can = vi.spyOn(engine, 'can').mockResolvedValue(true)
    const guard = iamNestAccessGuard<Action, ResourceType, RoleId, Scope>(engine, {
      getScope: () => 'org-1',
    })
    const handler = function h() {}
    Object.defineProperty(handler, '__accessMeta', {
      value: { action: 'delete', resource: 'post' },
    })
    const ctx = makeCtx({ user: { id: 'u' }, handler })
    await guard(ctx)
    expect(can.mock.calls[0]?.[4]).toBe('org-1')
    can.mockRestore()
  })

  it('onError handles engine throw - default returns false', async () => {
    vi.spyOn(engine, 'can').mockRejectedValue(new Error('boom'))
    const guard = iamNestAccessGuard(engine)
    const handler = function h() {}
    Object.defineProperty(handler, '__accessMeta', {
      value: { action: 'delete', resource: 'post' },
    })
    const ctx = makeCtx({ user: { id: 'u' }, handler })
    expect(await guard(ctx)).toBe(false)
  })

  it('custom onError can override result', async () => {
    vi.spyOn(engine, 'can').mockRejectedValue(new Error('boom'))
    const onError = vi.fn(() => true)
    const guard = iamNestAccessGuard(engine, { onError })
    const handler = function h() {}
    Object.defineProperty(handler, '__accessMeta', {
      value: { action: 'delete', resource: 'post' },
    })
    const ctx = makeCtx({ user: { id: 'u' }, handler })
    expect(await guard(ctx)).toBe(true)
    expect(onError).toHaveBeenCalledOnce()
  })
})

describe('createIamEngineProvider', () => {
  it('creates a NestJS provider with the engine token', () => {
    const factory = () => makeEngine()
    const provider = createIamEngineProvider(factory)
    expect(provider.provide).toBe(IAM_ACCESS_ENGINE_TOKEN)
    expect(provider.useFactory).toBe(factory)
  })

  it('exports stable engine token', () => {
    expect(IAM_ACCESS_ENGINE_TOKEN).toBe('ACCESS_ENGINE')
  })
})

describe('createIamAdminOperations onAdminMutation', () => {
  const flushMicrotasks = () => new Promise((r) => setTimeout(r, 0))

  function makeAdminReq(method: string, path = '/admin/policies') {
    return { method, path, route: { path } } as unknown as Parameters<
      ReturnType<typeof createIamAdminOperations<Action, ResourceType, RoleId, Scope>>['savePolicy']
    >[0]
  }

  it('csrfCheck rejecting throws 403 before authorize runs', async () => {
    const engine = makeEngine()
    let authorizeCalled = false
    let savedPolicy = false
    const origSave = engine.admin.savePolicy.bind(engine.admin)
    engine.admin.savePolicy = async (p) => {
      savedPolicy = true
      return origSave(p)
    }
    const h = createIamAdminOperations<Action, ResourceType, RoleId, Scope>(engine, {
      authorize: (() => {
        authorizeCalled = true
        return { id: 'admin-1' }
      }) as never,
      csrfCheck: (req) => (req as { headers: Record<string, string> }).headers['sec-fetch-site'] !== 'cross-site',
    })
    const req = {
      method: 'PUT',
      path: '/admin/policies',
      headers: { 'sec-fetch-site': 'cross-site' },
    } as never
    await expect(
      h.savePolicy(req, { id: 'p1', name: 'P', algorithm: 'deny-overrides', rules: [] } as never),
    ).rejects.toMatchObject({ status: 403 })
    expect(authorizeCalled).toBe(false)
    expect(savedPolicy).toBe(false)
  })

  it('savePolicy fires with action:replace, target:policy, success:true', async () => {
    const engine = makeEngine()
    const events: unknown[] = []
    const h = createIamAdminOperations<Action, ResourceType, RoleId, Scope>(engine, {
      authorize: (() => ({ id: 'admin-1' })) as never,
      onAdminMutation: (e) => {
        events.push(e)
      },
    })
    await h.savePolicy(makeAdminReq('PUT'), {
      id: 'p1',
      name: 'P',
      algorithm: 'deny-overrides',
      rules: [],
    } as unknown as AccessControl.IPolicy<Action, ResourceType, RoleId>)
    await flushMicrotasks()
    expect(events).toHaveLength(1)
    const ev = events[0] as {
      action: string
      target: string
      targetId?: string
      success: boolean
      method: string
      actor: unknown
    }
    expect(ev.action).toBe('replace')
    expect(ev.target).toBe('policy')
    expect(ev.targetId).toBe('p1')
    expect(ev.success).toBe(true)
    expect(ev.method).toBe('PUT')
    expect(ev.actor).toEqual({ id: 'admin-1' })
  })

  it('fires with success:false and error message when handler throws', async () => {
    const engine = makeEngine()
    const events: unknown[] = []
    const original = engine.admin.savePolicy
    engine.admin.savePolicy = async () => {
      throw new Error('save-failed')
    }
    const h = createIamAdminOperations<Action, ResourceType, RoleId, Scope>(engine, {
      authorize: () => true,
      onAdminMutation: (e) => {
        events.push(e)
      },
    })
    await expect(
      h.savePolicy(makeAdminReq('PUT'), {} as unknown as AccessControl.IPolicy<Action, ResourceType, RoleId>),
    ).rejects.toThrow('save-failed')
    await flushMicrotasks()
    engine.admin.savePolicy = original
    expect(events).toHaveLength(1)
    const ev = events[0] as { success: boolean; error?: string }
    expect(ev.success).toBe(false)
    // Default `event.error` is the class name, not `err.message`.
    expect(ev.error).toBe('Error')
  })

  it('does NOT fire on listPolicies / listRoles (reads)', async () => {
    const engine = makeEngine()
    const events: unknown[] = []
    const h = createIamAdminOperations<Action, ResourceType, RoleId, Scope>(engine, {
      authorize: () => true,
      onAdminMutation: (e) => {
        events.push(e)
      },
    })
    await h.listPolicies(makeAdminReq('GET'))
    await h.listRoles(makeAdminReq('GET'))
    await flushMicrotasks()
    expect(events).toHaveLength(0)
  })

  it('hook is fire-and-forget - a throwing hook does not affect the response', async () => {
    const engine = makeEngine()
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const h = createIamAdminOperations<Action, ResourceType, RoleId, Scope>(engine, {
      authorize: () => true,
      onAdminMutation: () => {
        throw new Error('hook-explode')
      },
    })
    const out = await h.savePolicy(makeAdminReq('PUT'), {
      id: 'p2',
      name: 'P',
      algorithm: 'deny-overrides',
      rules: [],
    } as unknown as AccessControl.IPolicy<Action, ResourceType, RoleId>)
    expect(out.ok).toBe(true)
    expect(errSpy).toHaveBeenCalled()
    errSpy.mockRestore()
  })

  it('redactPath rewrites event.path before the hook is called', async () => {
    const engine = makeEngine()
    const events: Array<{ path: string }> = []
    const h = createIamAdminOperations<Action, ResourceType, RoleId, Scope>(engine, {
      authorize: () => true,
      onAdminMutation: (e) => {
        events.push(e)
      },
      redactPath: (p) => p.replace(/\/[^/]+$/, '/:id'),
    })
    await h.revokeRole(
      makeAdminReq('DELETE', '/subjects/user-secret-42/roles/role-tenant-acme'),
      'user-secret-42',
      'role-tenant-acme' as RoleId,
    )
    await flushMicrotasks()
    expect(events).toHaveLength(1)
    expect(events[0]!.path).toBe('/subjects/user-secret-42/roles/:id')
    expect(events[0]!.path).not.toMatch(/role-tenant-acme/)
  })

  it('onAuditHookError receives thrown error and event', async () => {
    const engine = makeEngine()
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const captured: Array<{ err: unknown; event: { action: string; target: string } }> = []
    const boom = new Error('hook-boom')
    const h = createIamAdminOperations<Action, ResourceType, RoleId, Scope>(engine, {
      authorize: () => true,
      onAdminMutation: () => {
        throw boom
      },
      onAuditHookError: (err, event) => {
        captured.push({ err, event })
      },
    })
    await h.savePolicy(makeAdminReq('PUT'), {
      id: 'p3',
      name: 'P',
      algorithm: 'deny-overrides',
      rules: [],
    } as unknown as AccessControl.IPolicy<Action, ResourceType, RoleId>)
    await flushMicrotasks()
    expect(captured).toHaveLength(1)
    expect(captured[0]!.err).toBe(boom)
    expect(captured[0]!.event.action).toBe('replace')
    expect(captured[0]!.event.target).toBe('policy')
    expect(errSpy).not.toHaveBeenCalled()
    errSpy.mockRestore()
  })

  it('event.error defaults to the error class name', async () => {
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
    const h = createIamAdminOperations<Action, ResourceType, RoleId, Scope>(engine, {
      authorize: () => true,
      onAdminMutation: (e) => {
        events.push(e)
      },
    })
    await expect(
      h.savePolicy(makeAdminReq('PUT'), {} as unknown as AccessControl.IPolicy<Action, ResourceType, RoleId>),
    ).rejects.toBeInstanceOf(PolicyValidationError)
    await flushMicrotasks()
    engine.admin.savePolicy = original
    expect(events).toHaveLength(1)
    expect(events[0]!.error).toBe('PolicyValidationError')
    expect(events[0]!.error).not.toMatch(/password/)
  })

  it('includeErrorMessage:true restores err.message', async () => {
    const engine = makeEngine()
    const events: Array<{ error?: string }> = []
    const original = engine.admin.savePolicy
    engine.admin.savePolicy = async () => {
      throw new Error('full-detailed-message')
    }
    const h = createIamAdminOperations<Action, ResourceType, RoleId, Scope>(engine, {
      authorize: () => true,
      includeErrorMessage: true,
      onAdminMutation: (e) => {
        events.push(e)
      },
    })
    await expect(
      h.savePolicy(makeAdminReq('PUT'), {} as unknown as AccessControl.IPolicy<Action, ResourceType, RoleId>),
    ).rejects.toThrow('full-detailed-message')
    await flushMicrotasks()
    engine.admin.savePolicy = original
    expect(events[0]!.error).toBe('full-detailed-message')
  })

  it('merges getResourceAttributes into the resource passed to engine.can', async () => {
    const canSpy = vi.fn().mockResolvedValue(true)
    const engine = { can: canSpy } as unknown as IamEngine<string, string, string, string>

    const guard = iamNestAccessGuard(engine, {
      getUserId: () => 'user-1',
      // `undefined` is not an AttributeValue; an absent owner is expressed as null.
      getResourceAttributes: (req) => ({ ownerId: (req as { ownerId?: string }).ownerId ?? null }),
    })

    const handler = (): void => {}
    Object.defineProperty(handler, '__accessMeta', { value: { action: 'read', resource: 'widgets' } })

    const ctx = {
      switchToHttp: () => ({ getRequest: () => ({ ownerId: 'user-1', method: 'GET' }) }),
      getHandler: () => handler,
    }

    await guard(ctx as never)

    expect(canSpy).toHaveBeenCalledWith(
      'user-1',
      'read',
      { type: 'widgets', id: undefined, attributes: { ownerId: 'user-1' } },
      expect.anything(),
      undefined,
    )
  })
})
