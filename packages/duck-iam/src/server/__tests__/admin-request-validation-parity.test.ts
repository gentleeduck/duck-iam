import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../adapters/memory'
import { IamEngine } from '../../core/engine'
import type { AccessControl } from '../../core/types'
import { iamAdminRouter } from '../express'
import { iamBindAdminRouter } from '../hono'
import { createIamAdminOperations } from '../nest'
import { createIamAdminHandlers } from '../next'

/**
 * One malformed admin request, four adapters, four different answers.
 *
 * `POST /subjects/:id/roles` with `{"roleId": ""}` was a **400** on hono, which
 * hand-rolled its own checks inline, and a **500** on express, next and nest,
 * whose shared validators threw a bare `Error` that every generic `catch`
 * routes to `onError`. `{"roleId": "   "}` was a **write** on all four: the
 * checks read `length === 0`, so a blank id became a real grant on a role that
 * renders as nothing at all in an admin UI. And a 200-char `roleId` was a 400
 * on hono, which capped at 128, and a write on the other three, which let the
 * engine's own 1024 decide.
 *
 * A client cannot be written against "the admin API" while the status code and
 * the length limit depend on which adapter the operator mounted. These tests
 * drive the same body through all four and require one answer.
 *
 * Each adapter is exercised through its real entry point rather than through
 * the shared validator directly - the validator agreeing with itself proves
 * nothing about the adapter that has to call it.
 */
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
  // Express never sees raw bytes: its host parses the body and answers 400 for
  // malformed JSON before any handler runs. `onError` answers 500, which is
  // what these cases used to reach.
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

/**
 * @param json - Stands in for hono's own parser, so a case can make it throw
 *   the way a truncated upload does.
 */
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
  // Nest throws rather than writing a response, and its own filter reads
  // `statusCode` off the thrown error - so that field *is* the status here.
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
  // Control. Without this every assertion below is satisfied by an adapter that
  // refuses everything, which is not what is being claimed.
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
  /**
   * Hono capped at 128 and the others did not cap at all. 1024 is the engine's
   * own cap (`assertNonEmptyStringParam`), so the edge now refuses exactly what
   * the engine would refuse and no adapter refuses an id another accepts.
   */
  it('a 200-char roleId is not refused for its length by any adapter', async () => {
    // 200 is over hono's old 128 and under the shared 1024. It is not a role
    // that exists, so the engine refuses it - the point is that all four now
    // fail the same way, rather than one failing earlier than the rest.
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

/**
 * Hono and next call the parser *inside* the audited handler, so a `SyntaxError`
 * from a truncated upload or a form post carrying a JSON content-type landed in
 * the generic `catch`, was handed to `onError` as though the package had broken,
 * and answered 500 - telling the client to retry bytes that will never parse.
 *
 * Express and nest are absent here on purpose: their hosts parse the body and
 * answer 400 themselves, so neither ever sees the raw bytes. That is the
 * behaviour the other two now match.
 */
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
    // The parser's message quotes the offending input, which is
    // caller-controlled content on its way into an operator's log.
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
