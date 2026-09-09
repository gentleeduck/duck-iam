import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../adapters/memory'
import { IamEngine } from '../../core/engine'
import { iamAdminRouter } from '../express'
import type { IamAdminAudit } from '../generic'
import { iamBindAdminRouter } from '../hono'
import { createIamAdminOperations } from '../nest'
import { createIamAdminHandlers } from '../next'

/**
 * The admin surface had no cross-adapter suite, and it is the highest-privilege
 * surface in the package: it writes policies and grants roles. The *request*
 * path has `cross-adapter.test.ts`; these four routers were each tested only
 * inside their own file, and they drifted.
 *
 * What the drift produced, all of it found by comparing them rather than by
 * reading any one of them:
 *
 * - `{"roleId":"editor","scope":null}` was a **global** role grant on express
 *   and a refusal on the other three. A client written against hono that
 *   spells "unset" as `null` would have widened every grant it made the day
 *   the deployment moved.
 * - next and nest ran `assignRole`/`revokeRole` with no edge validation at all,
 *   so a number, an empty string, an array body or a missing `:id` reached
 *   `engine.admin.*`. Nothing bad landed, because the engine refuses each one -
 *   but the refusal was wholly delegated, and a consumer with a custom adapter
 *   that does not repeat those checks lost it.
 * - nest hand-rolled the authorize gate, so the documented
 *   `authorize: (req) => req.user?.role === 'admin'` wrote `actor: true` into
 *   the audit trail where the others write `undefined` and warn.
 * - hono returned its inline 400s from *inside* the audited handler, so a
 *   refused role assignment was recorded as `success: true` - an audit trail
 *   inventing grants that were never made.
 * - hono and next recorded `PUT /policies` with no `targetId`: a trail saying a
 *   policy was replaced without saying which one.
 *
 * One harness cannot drive all four - express mutates a `res`, hono returns
 * from `c.json`, next takes a WHATWG `Request`, nest throws - so there are four
 * thin runners below reducing each to one `IOutcome`, and a single clause list
 * over them.
 */
interface IOutcome {
  /** HTTP status, where the adapter produces one. `undefined` when it threw instead. */
  readonly status: number | undefined
  /** What the adapter threw, if anything. */
  readonly thrown: unknown
  /** Every `engine.admin.assignRole` call that actually reached the engine. */
  readonly assigned: readonly unknown[][]
  /** Audit events the adapter fired. */
  readonly events: readonly IamAdminAudit.IEvent[]
}

interface IAdminRunner {
  readonly name: string
  /** `POST /subjects/:id/roles`. `params` may deliberately be missing `id`. */
  assignRole(opts: IRunOpts, params: Record<string, string>, body: unknown): Promise<IOutcome>
  /** `PUT /policies`. */
  savePolicy(opts: IRunOpts, body: unknown): Promise<IOutcome>
}

interface IRunOpts {
  authorize?: (req: never) => unknown
  csrfCheck?: ((req: never) => boolean) | false
}

const POLICY = { algorithm: 'deny-overrides', id: 'p-audit', name: 'P', rules: [] }

function makeEngine() {
  const adapter = new IamMemoryAdapter({
    assignments: { 'user-1': ['editor'] },
    roles: [{ id: 'editor', name: 'Editor', permissions: [{ action: 'read', resource: 'post' }] }],
  })
  return new IamEngine({ adapter, cacheTTL: 0 })
}

/** Engine plus the recorders every runner shares. */
function makeHarness(opts: IRunOpts) {
  const engine = makeEngine()
  const assigned: unknown[][] = []
  vi.spyOn(engine.admin, 'assignRole').mockImplementation(async (...args: unknown[]) => {
    assigned.push(args)
  })
  const events: IamAdminAudit.IEvent[] = []
  const adminOpts = {
    authorize: opts.authorize ?? (() => true),
    csrfCheck: opts.csrfCheck ?? false,
    onAdminMutation: (e: IamAdminAudit.IEvent) => {
      events.push(e)
    },
  }
  return { adminOpts, assigned, engine, events }
}

/** Runs `fn`, turning a throw into part of the outcome rather than a failure. */
async function capture(
  fn: () => Promise<number | undefined>,
  assigned: unknown[][],
  events: IamAdminAudit.IEvent[],
): Promise<IOutcome> {
  try {
    const status = await fn()
    await new Promise((r) => setTimeout(r, 0))
    return { assigned, events, status, thrown: undefined }
  } catch (err) {
    await new Promise((r) => setTimeout(r, 0))
    return { assigned, events, status: undefined, thrown: err }
  }
}

const expressRunner: IAdminRunner = {
  name: 'express',
  async assignRole(opts, params, body) {
    const { adminOpts, assigned, engine, events } = makeHarness(opts)
    const { call, res } = mountExpress(engine, adminOpts)
    return capture(
      async () => {
        await call('POST /subjects/:id/roles', { body, method: 'POST', params })
        return res.statusCode
      },
      assigned,
      events,
    )
  },
  async savePolicy(opts, body) {
    const { adminOpts, assigned, engine, events } = makeHarness(opts)
    const { call, res } = mountExpress(engine, adminOpts)
    return capture(
      async () => {
        await call('PUT /policies', { body, method: 'PUT' })
        return res.statusCode
      },
      assigned,
      events,
    )
  },
}

function mountExpress(engine: ReturnType<typeof makeEngine>, adminOpts: object) {
  type Handler = (req: never, res: never) => Promise<void> | void
  const handlers: Record<string, Handler> = {}
  const record = (verb: string) => (path: string, h: Handler) => {
    handlers[`${verb} ${path}`] = h
  }
  const router = {
    delete: vi.fn(record('DELETE')),
    get: vi.fn(record('GET')),
    post: vi.fn(record('POST')),
    put: vi.fn(record('PUT')),
  }
  const res = {
    body: undefined as unknown,
    json(b: unknown) {
      this.body = b
    },
    status(code: number) {
      this.statusCode = code
      return this
    },
    statusCode: 200,
  }
  // The adapter's `onError` default writes 500; nothing here overrides it, so
  // the status is the adapter's own answer rather than the harness's.
  iamAdminRouter(engine, adminOpts as never)(() => router as never)
  const call = (key: string, req: unknown) => handlers[key]?.(req as never, res as never)
  return { call, res }
}

const honoRunner: IAdminRunner = {
  name: 'hono',
  async assignRole(opts, params, body) {
    const { adminOpts, assigned, engine, events } = makeHarness(opts)
    const { call } = mountHono(engine, adminOpts)
    return capture(
      () => call('POST /subjects/:id/roles', { body, method: 'POST', params, path: '/subjects/x/roles' }),
      assigned,
      events,
    )
  },
  async savePolicy(opts, body) {
    const { adminOpts, assigned, engine, events } = makeHarness(opts)
    const { call } = mountHono(engine, adminOpts)
    return capture(() => call('PUT /policies', { body, method: 'PUT', path: '/policies' }), assigned, events)
  },
}

function mountHono(engine: ReturnType<typeof makeEngine>, adminOpts: object) {
  type Handler = (c: unknown) => Promise<Response> | Response
  const handlers: Record<string, Handler> = {}
  const record = (verb: string) => (path: string, h: Handler) => {
    handlers[`${verb} ${path}`] = h
  }
  const router = {
    delete: vi.fn(record('DELETE')),
    get: vi.fn(record('GET')),
    post: vi.fn(record('POST')),
    put: vi.fn(record('PUT')),
  }
  iamBindAdminRouter(router, engine, adminOpts as never)
  const call = async (
    key: string,
    o: { params?: Record<string, string>; body?: unknown; method: string; path: string },
  ): Promise<number> => {
    const ctx = {
      json: (data: unknown, status?: number) => ({ data, status: status ?? 200 }),
      req: {
        header: () => undefined,
        json: async () => o.body,
        method: o.method,
        param: (n: string) => o.params?.[n],
        path: o.path,
      },
    }
    const out = await handlers[key]?.(ctx as never)
    return (out as unknown as { status: number }).status
  }
  return { call }
}

const nextRunner: IAdminRunner = {
  name: 'next',
  async assignRole(opts, params, body) {
    const { adminOpts, assigned, engine, events } = makeHarness(opts)
    const h = createIamAdminHandlers(engine, adminOpts as never)
    const req = new Request('https://x.test/api/admin/subjects/x/roles', {
      body: JSON.stringify(body),
      headers: { 'content-type': 'application/json' },
      method: 'POST',
    })
    return capture(async () => (await h.assignRole(req, { params } as never)).status, assigned, events)
  },
  async savePolicy(opts, body) {
    const { adminOpts, assigned, engine, events } = makeHarness(opts)
    const h = createIamAdminHandlers(engine, adminOpts as never)
    const req = new Request('https://x.test/api/admin/policies', {
      body: JSON.stringify(body),
      headers: { 'content-type': 'application/json' },
      method: 'PUT',
    })
    return capture(async () => (await h.savePolicy(req, { params: {} } as never)).status, assigned, events)
  },
}

const nestRunner: IAdminRunner = {
  name: 'nest',
  async assignRole(opts, params, body) {
    const { adminOpts, assigned, engine, events } = makeHarness(opts)
    const ops = createIamAdminOperations(engine, adminOpts as never)
    const req = { headers: {}, method: 'POST', path: '/subjects/x/roles' }
    return capture(
      async () => {
        await ops.assignRole(req as never, params.id as never, body as never)
        return 200
      },
      assigned,
      events,
    )
  },
  async savePolicy(opts, body) {
    const { adminOpts, assigned, engine, events } = makeHarness(opts)
    const ops = createIamAdminOperations(engine, adminOpts as never)
    const req = { headers: {}, method: 'PUT', path: '/policies' }
    return capture(
      async () => {
        await ops.savePolicy(req as never, body as never)
        return 200
      },
      assigned,
      events,
    )
  },
}

const RUNNERS = [expressRunner, honoRunner, nextRunner, nestRunner]

/** Refused = the engine was never asked to make the grant. */
function wasRefused(out: IOutcome): boolean {
  return out.assigned.length === 0
}

describe.each(RUNNERS.map((r) => [r.name, r] as const))('admin parity: %s', (_name, runner) => {
  describe('a role grant is refused unless the body and path say exactly what to grant', () => {
    const BAD_BODIES: [string, unknown][] = [
      ['an explicit null scope', { roleId: 'editor', scope: null }],
      ['a numeric roleId', { roleId: 7 }],
      ['an empty roleId', { roleId: '' }],
      ['a missing roleId', {}],
      ['a numeric scope', { roleId: 'editor', scope: 7 }],
      ['an empty scope', { roleId: 'editor', scope: '' }],
      ['an array body', ['editor']],
      ['a string body', 'editor'],
      ['a null body', null],
    ]

    it.each(BAD_BODIES)('%s never reaches engine.admin.assignRole', async (_label, body) => {
      expect(wasRefused(await runner.assignRole({}, { id: 'user-1' }, body))).toBe(true)
    })

    it('a missing :id never reaches the engine', async () => {
      expect(wasRefused(await runner.assignRole({}, {}, { roleId: 'editor' }))).toBe(true)
    })

    it('an empty :id never reaches the engine', async () => {
      expect(wasRefused(await runner.assignRole({}, { id: '' }, { roleId: 'editor' }))).toBe(true)
    })

    // Control. Without this every clause above is satisfied by an adapter that
    // refuses everything, which would tell us nothing.
    it('a well-formed grant does reach the engine', async () => {
      const out = await runner.assignRole({}, { id: 'user-1' }, { roleId: 'editor', scope: 'org-1' })
      expect(out.assigned).toEqual([['user-1', 'editor', 'org-1']])
    })

    it('a well-formed grant with no scope reaches the engine unscoped', async () => {
      const out = await runner.assignRole({}, { id: 'user-1' }, { roleId: 'editor' })
      expect(out.assigned).toEqual([['user-1', 'editor', undefined]])
    })
  })

  describe('the audit trail says what actually happened', () => {
    it('a refused grant is never recorded as a successful mutation', async () => {
      const out = await runner.assignRole({}, { id: 'user-1' }, { roleId: 7 })
      expect(out.events.every((e) => e.success === false)).toBe(true)
    })

    it('a boolean authorize answer is never recorded as the actor', async () => {
      // `authorize: (req) => req.user?.role === 'admin'` is the documented
      // shape and returns a boolean. It authorizes; it does not name anyone.
      const out = await runner.assignRole({ authorize: () => true }, { id: 'user-1' }, { roleId: 'editor' })
      expect(out.events.length).toBeGreaterThan(0)
      for (const e of out.events) expect(e.actor).toBeUndefined()
    })

    it('an actor that does name someone is kept', async () => {
      const out = await runner.assignRole(
        { authorize: () => ({ id: 'admin-7' }) },
        { id: 'user-1' },
        { roleId: 'editor' },
      )
      for (const e of out.events) expect(e.actor).toEqual({ id: 'admin-7' })
    })

    it('savePolicy records which policy was replaced', async () => {
      const out = await runner.savePolicy({}, POLICY)
      expect(out.events.length).toBeGreaterThan(0)
      for (const e of out.events) expect(e.targetId).toBe('p-audit')
    })

    it('a grant records the subject it was for', async () => {
      const out = await runner.assignRole({}, { id: 'user-1' }, { roleId: 'editor' })
      for (const e of out.events) expect(e.targetId).toBe('user-1')
    })
  })

  describe('the gate', () => {
    it('a csrfCheck that returns false refuses the grant', async () => {
      const out = await runner.assignRole({ csrfCheck: () => false }, { id: 'user-1' }, { roleId: 'editor' })
      expect(wasRefused(out)).toBe(true)
    })

    it('a csrfCheck that throws refuses the grant rather than escaping', async () => {
      // A predicate that cannot answer has not said yes. This used to
      // propagate raw on nest while the other three failed closed to 403.
      const out = await runner.assignRole(
        {
          csrfCheck: () => {
            throw new Error('boom')
          },
        },
        { id: 'user-1' },
        { roleId: 'editor' },
      )
      expect(wasRefused(out)).toBe(true)
      expect(String(out.thrown ?? '')).not.toContain('boom')
    })

    it('authorize returning false refuses the grant and fires no audit event', async () => {
      const out = await runner.assignRole({ authorize: () => false }, { id: 'user-1' }, { roleId: 'editor' })
      expect(wasRefused(out)).toBe(true)
      expect(out.events).toEqual([])
    })
  })
})
