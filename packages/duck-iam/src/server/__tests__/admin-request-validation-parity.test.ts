import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../adapters/memory'
import { IamEngine } from '../../core/engine'
import type { AccessControl } from '../../core/types'
import { iamAdminRouter } from '../express'
import { iamBindAdminRouter } from '../hono'
import { createIamAdminOperations } from '../nest'
import { createIamAdminHandlers } from '../next'

// Drives one malformed admin request through all four admin routers' real entry points and requires one answer:
// the same status and the same length limit, whichever adapter is mounted.
type Action = 'read' | 'create'
type ResourceType = 'post'
type RoleId = 'editor'
type Scope = 'org-1'

const editorRole: AccessControl.IRole<Action, ResourceType, RoleId, Scope> = {
  id: 'editor',
  name: 'Editor',
  permissions: [{ action: 'create', resource: 'post' }],
}

function makeEngine() {
  const adapter = new IamMemoryAdapter<Action, ResourceType, RoleId, Scope>({ assignments: {}, roles: [editorRole] })
  return {
    adapter,
    engine: new IamEngine<Action, ResourceType, RoleId, Scope>({ adapter, cacheTTL: 0 }),
  }
}

/** What every adapter run is reduced to, so the four can be compared at all. */
interface Attempt {
  /** The HTTP status the caller would receive. */
  status: number
  /** Every role id written to the store, scoped or not. */
  written: readonly string[]
}

async function written(adapter: IamMemoryAdapter<Action, ResourceType, RoleId, Scope>): Promise<readonly string[]> {
  const unscoped = await adapter.getSubjectRoles('u1')
  const scoped = await adapter.getSubjectScopedRoles('u1')
  return [...unscoped, ...scoped.map((s) => s.role)]
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

async function expressAssign(body: unknown, id = 'u1'): Promise<Attempt> {
  const { adapter, engine } = makeEngine()
  const { handlers, router } = recordingRouter()
  // INFO: the Express host parses the body and answers 400 for malformed JSON before any handler runs.
  iamAdminRouter(engine, { authorize: () => true, onError: (_e, _q, res) => res.status(500).json({}) })(
    () => router as never,
  )
  const res = {
    statusCode: 200,
    json() {
      return this
    },
    status(code: number) {
      this.statusCode = code
      return this
    },
  }
  await handlers['POST /subjects/:id/roles']!({ body, params: { id } } as never, res as never)
  return { status: res.statusCode, written: await written(adapter) }
}

/** @param json - Stands in for hono's parser, so a case can make it throw like a truncated upload. */
async function honoAssign(json: () => Promise<unknown>, id = 'u1'): Promise<Attempt> {
  const { adapter, engine } = makeEngine()
  const { handlers, router } = recordingRouter()
  iamBindAdminRouter(router as never, engine, {
    authorize: () => true,
    onError: () => new Response(null, { status: 500 }),
  })
  const ctx = {
    json: (data: unknown, status = 200) => new Response(JSON.stringify(data), { status }),
    req: {
      header: () => undefined,
      json,
      method: 'POST',
      param: (name: string) => (name === 'id' ? id : undefined),
      path: '/subjects/u1/roles',
      url: 'https://example.com/subjects/u1/roles',
    },
  }
  const res = (await handlers['POST /subjects/:id/roles']!(ctx as never)) as Response
  return { status: res.status, written: await written(adapter) }
}

async function nextAssign(rawBody: string, id = 'u1'): Promise<Attempt> {
  const { adapter, engine } = makeEngine()
  const handlers = createIamAdminHandlers<Action, ResourceType, RoleId, Scope>(engine, {
    authorize: () => true,
    onError: () => Response.json({}, { status: 500 }),
  })
  const req = new Request('https://example.com/api/admin/subjects/u1/roles', {
    body: rawBody,
    headers: { 'content-type': 'application/json' },
    method: 'POST',
  })
  const res = await handlers.assignRole(req, { params: { id } })
  return { status: res.status, written: await written(adapter) }
}

async function nestAssign(body: unknown, id = 'u1'): Promise<Attempt> {
  const { adapter, engine } = makeEngine()
  const ops = createIamAdminOperations<Action, ResourceType, RoleId, Scope>(engine, { authorize: () => true })
  // Nest throws rather than writing a response, and its filter reads the status off the error's `statusCode`.
  const req = { method: 'POST', path: '/admin/subjects/u1/roles', route: { path: '/admin/subjects/:id/roles' } }
  let status = 200
  try {
    await ops.assignRole(req as never, id, body as never)
  } catch (err) {
    const code: unknown = (err as { statusCode?: unknown }).statusCode
    status = typeof code === 'number' ? code : 500
  }
  return { status, written: await written(adapter) }
}

/** Runs one body through all four adapters. */
async function allFour(body: unknown, id = 'u1'): Promise<Record<string, Attempt>> {
  return {
    express: await expressAssign(body, id),
    hono: await honoAssign(async () => body, id),
    nest: await nestAssign(body, id),
    next: await nextAssign(JSON.stringify(body), id),
  }
}

describe('the four admin routers answer one bad request the same way', () => {
  // Control: an adapter that refused everything would satisfy every assertion below.
  it('a well-formed assignment is written by all four', async () => {
    for (const [name, attempt] of Object.entries(await allFour({ roleId: 'editor', scope: 'org-1' }))) {
      expect(attempt.written, name).toEqual(['editor'])
      expect(attempt.status, name).toBe(200)
    }
  })

  it.each([
    ['a blank roleId', { roleId: '   ' }],
    ['a tab-only roleId', { roleId: '\t' }],
    ['an empty roleId', { roleId: '' }],
    ['a missing roleId', {}],
    ['a numeric roleId', { roleId: 7 }],
    ['a blank scope', { roleId: 'editor', scope: ' ' }],
    ['an explicit null scope', { roleId: 'editor', scope: null }],
    ['a non-object body', 'editor'],
  ])('%s is a 400 on all four, and writes nothing', async (_label, body) => {
    for (const [name, attempt] of Object.entries(await allFour(body))) {
      expect(attempt.status, name).toBe(400)
      expect(attempt.written, name).toEqual([])
    }
  })

  it('a blank :id is a 400 on all four, and writes nothing', async () => {
    for (const [name, attempt] of Object.entries(await allFour({ roleId: 'editor' }, '  '))) {
      expect(attempt.status, name).toBe(400)
      expect(attempt.written, name).toEqual([])
    }
  })
})

describe('the length cap on an admin id is the same on all four', () => {
  // 1024 is the engine's own cap (`assertNonEmptyStringParam`), so the edge refuses exactly what the engine would.
  it('a 200-char roleId is not refused for its length by any adapter', async () => {
    // Under the cap but not a real role: the engine refuses it, and all four must fail the same way.
    const statuses = Object.values(await allFour({ roleId: 'x'.repeat(200) })).map((a) => a.status)
    expect(new Set(statuses).size).toBe(1)
    expect(statuses[0]).not.toBe(400)
  })

  it('a 1025-char roleId is a 400 on all four', async () => {
    for (const [name, attempt] of Object.entries(await allFour({ roleId: 'x'.repeat(1025) }))) {
      expect(attempt.status, name).toBe(400)
      expect(attempt.written, name).toEqual([])
    }
  })
})

// Hono and next parse inside the handler, so a `SyntaxError` must be a 400, not a retryable 500.
// Express and nest hosts parse the body and answer 400 themselves.
describe("a body that is not JSON is the caller's mistake on the adapters that parse it", () => {
  it('hono answers 400 rather than routing a SyntaxError to onError', async () => {
    const attempt = await honoAssign(() => Promise.reject(new SyntaxError('Unexpected end of JSON input')))
    expect(attempt.status).toBe(400)
    expect(attempt.written).toEqual([])
  })

  it('next answers 400 for a truncated body', async () => {
    const attempt = await nextAssign('{"roleId": "edi')
    expect(attempt.status).toBe(400)
    expect(attempt.written).toEqual([])
  })

  it('the refusal does not echo the unparsable bytes back to the caller', async () => {
    // SECURITY: the parser's message quotes the caller-controlled input.
    const { engine } = makeEngine()
    const handlers = createIamAdminHandlers<Action, ResourceType, RoleId, Scope>(engine, { authorize: () => true })
    const req = new Request('https://example.com/api/admin/subjects/u1/roles', {
      body: '{"roleId": "s3cr3t-tenant-name',
      headers: { 'content-type': 'application/json' },
      method: 'POST',
    })
    const res = await handlers.assignRole(req, { params: { id: 'u1' } })
    expect(await res.text()).not.toContain('s3cr3t-tenant-name')
  })
})
