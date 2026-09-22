import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../adapters/memory'
import { IamEngine } from '../../core/engine'
import type { AccessControl } from '../../core/types'
import { iamAdminRouter } from '../express'
import type { IamAdminActor, IamAdminAuthzAnswer } from '../generic'
import { iamBindAdminRouter } from '../hono'
import { createIamAdminOperations } from '../nest'
import { createIamAdminHandlers } from '../next'

// The routers authenticate an actor for their own audit hook. The same actor has to reach `engine.admin`, or the
// adapter's `created_by` / `updated_by` and the engine's `onMutation` record an HTTP write as nobody's.
type Action = 'read'
type ResourceType = 'post'
type RoleId = 'reader'
type Scope = 'org-1'

const ROLE: AccessControl.IRole<Action, ResourceType, RoleId, Scope> = {
  id: 'reader',
  name: 'Reader',
  permissions: [{ action: 'read', resource: 'post' }],
}

const POLICY: AccessControl.IPolicy<Action, ResourceType, RoleId> = {
  algorithm: 'deny-overrides',
  id: 'p1',
  name: 'p1',
  rules: [{ actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 1, resources: ['post'] }],
}

class Recorder extends IamMemoryAdapter<Action, ResourceType, RoleId, Scope> {
  seen: (string | null)[] = []
  async assignRole(id: string, roleId: RoleId, scope?: Scope, opts?: { actor?: string }) {
    this.seen.push(opts?.actor ?? null)
    return super.assignRole(id, roleId, scope, opts)
  }
  async savePolicy(p: AccessControl.IPolicy<Action, ResourceType, RoleId>, opts?: { actor?: string }) {
    this.seen.push(opts?.actor ?? null)
    return super.savePolicy(p)
  }
}

/** What one run through one router is reduced to, so the four can be compared. */
interface Run {
  /** The actor the adapter was told, per write. */
  adapter: (string | null)[]
  /** The actor `onMutation` carried, per event. */
  engine: (string | null)[]
  /** The actor the router's own audit hook recorded. */
  audit: unknown[]
}

type Opts = {
  authorize: () => IamAdminAuthzAnswer
  getMutationActor?: (actor: IamAdminActor) => string | undefined
}

/** A `getMutationActor` for the claims-object case, narrowed rather than cast. */
function subOf(actor: IamAdminActor): string | undefined {
  if (typeof actor !== 'object') return undefined
  const sub: unknown = Reflect.get(actor, 'sub')
  return typeof sub === 'string' ? sub : undefined
}

type Handler = (...args: never[]) => Promise<unknown> | unknown

function recordingRouter(): { handlers: Record<string, Handler>; router: Record<string, unknown> } {
  const handlers: Record<string, Handler> = {}
  const record = (method: string) => (path: string, h: Handler) => {
    handlers[`${method} ${path}`] = h
  }
  return {
    handlers,
    router: {
      delete: vi.fn(record('DELETE')),
      get: vi.fn(record('GET')),
      post: vi.fn(record('POST')),
      put: vi.fn(record('PUT')),
    },
  }
}

function make(audit: unknown[]) {
  const adapter = new Recorder({ roles: [ROLE] })
  const engineActors: (string | null)[] = []
  const engine = new IamEngine<Action, ResourceType, RoleId, Scope>({
    adapter,
    cacheTTL: 0,
    hooks: { onMutation: (e) => void engineActors.push(e.actor ?? null) },
  })
  const audited = (e: { actor?: unknown }) => void audit.push(e.actor ?? null)
  return { adapter, audited, engine, engineActors }
}

/** Each router, driven through its real entry points: one assignment and one policy save. */
const SURFACES: { name: string; run: (opts: Opts) => Promise<Run> }[] = [
  {
    name: 'express',
    async run(opts) {
      const audit: unknown[] = []
      const { adapter, audited, engine, engineActors } = make(audit)
      const { handlers, router } = recordingRouter()
      iamAdminRouter(engine, {
        ...opts,
        onAdminMutation: audited,
        onError: (_e, _q, res) => res.status(500).json({}),
      })(() => router as never)
      const res = {
        json() {
          return this
        },
        status() {
          return this
        },
      }
      await handlers['POST /subjects/:id/roles']!(
        { body: { roleId: 'reader' }, params: { id: 'u1' } } as never,
        res as never,
      )
      await handlers['PUT /policies']!({ body: POLICY } as never, res as never)
      return { adapter: adapter.seen, audit, engine: engineActors }
    },
  },
  {
    name: 'hono',
    async run(opts) {
      const audit: unknown[] = []
      const { adapter, audited, engine, engineActors } = make(audit)
      const { handlers, router } = recordingRouter()
      iamBindAdminRouter(router as never, engine, {
        ...opts,
        onAdminMutation: audited,
        onError: () => new Response(null, { status: 500 }),
      })
      const ctx = (body: unknown) => ({
        json: (d: unknown, s = 200) => new Response(JSON.stringify(d), { status: s }),
        req: {
          header: () => undefined,
          json: async () => body,
          method: 'POST',
          param: () => 'u1',
          path: '/subjects/u1/roles',
          url: 'https://example.com/subjects/u1/roles',
        },
      })
      await handlers['POST /subjects/:id/roles']!(ctx({ roleId: 'reader' }) as never)
      await handlers['PUT /policies']!(ctx(POLICY) as never)
      return { adapter: adapter.seen, audit, engine: engineActors }
    },
  },
  {
    name: 'nest',
    async run(opts) {
      const audit: unknown[] = []
      const { adapter, audited, engine, engineActors } = make(audit)
      const ops = createIamAdminOperations<Action, ResourceType, RoleId, Scope>(engine, {
        ...opts,
        onAdminMutation: audited,
      })
      const req = { method: 'POST', path: '/admin/subjects/u1/roles', route: { path: '/admin/subjects/:id/roles' } }
      await ops.assignRole(req as never, 'u1', { roleId: 'reader' })
      await ops.savePolicy(req as never, POLICY)
      return { adapter: adapter.seen, audit, engine: engineActors }
    },
  },
  {
    name: 'next',
    async run(opts) {
      const audit: unknown[] = []
      const { adapter, audited, engine, engineActors } = make(audit)
      const handlers = createIamAdminHandlers<Action, ResourceType, RoleId, Scope>(engine, {
        ...opts,
        onAdminMutation: audited,
        onError: () => Response.json({}, { status: 500 }),
      })
      const req = (url: string, body: unknown) =>
        new Request(url, {
          body: JSON.stringify(body),
          headers: { 'content-type': 'application/json' },
          method: 'POST',
        })
      await handlers.assignRole(req('https://example.com/api/admin/subjects/u1/roles', { roleId: 'reader' }), {
        params: { id: 'u1' },
      })
      await handlers.savePolicy(req('https://example.com/api/admin/policies', POLICY), { params: {} })
      return { adapter: adapter.seen, audit, engine: engineActors }
    },
  },
]

describe('the actor an admin router authenticated', () => {
  it.each(SURFACES)('$name forwards a string actor to the adapter and to onMutation', async ({ run }) => {
    const out = await run({ authorize: () => 'alice' })
    expect(out.adapter).toEqual(['alice', 'alice'])
    expect(out.engine).toEqual(['alice', 'alice'])
    expect(out.audit).toEqual(['alice', 'alice'])
  })

  // Control: the recorders report `null`, so the assertions above cannot pass by accident.
  it.each(SURFACES)('$name records no actor when authorize names no one', async ({ run }) => {
    const out = await run({ authorize: () => true })
    expect(out.adapter).toEqual([null, null])
    expect(out.engine).toEqual([null, null])
    expect(out.audit).toEqual([null, null])
  })

  // An object actor is the audit hook's business; the engine takes a string, and guessing a field would be wrong.
  it.each(SURFACES)('$name leaves an object actor to getMutationActor', async ({ run }) => {
    const claims = { sub: 'alice' }
    const without = await run({ authorize: () => claims })
    expect(without.adapter).toEqual([null, null])
    expect(without.audit).toEqual([claims, claims])

    const mapped = await run({ authorize: () => claims, getMutationActor: subOf })
    expect(mapped.adapter).toEqual(['alice', 'alice'])
    expect(mapped.engine).toEqual(['alice', 'alice'])
    expect(mapped.audit).toEqual([claims, claims])
  })

  it.each(SURFACES)('$name ignores a getMutationActor that names no one', async ({ run }) => {
    const out = await run({ authorize: () => 'alice', getMutationActor: () => '   ' })
    expect(out.adapter).toEqual([null, null])
    expect(out.audit).toEqual(['alice', 'alice'])
  })
})
