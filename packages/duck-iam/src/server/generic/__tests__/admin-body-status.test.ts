import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../../core/engine/engine'
import { hasIamErrorCode, IamError } from '../../../core/errors'
import { iamAdminRouter } from '../../express'
import { iamBindAdminRouter } from '../../hono'
import { createIamAdminHandlers } from '../../next'

// A body the validator rejects is the caller's error: a 400, not a 500 from `onError` that invites retries and
// hides a client bug behind an apparent outage.

type Res = {
  statusCode: number
  body: unknown
  status(code: number): Res
  json(body: unknown): void
}

function makeRes(): Res {
  const res: Res = {
    statusCode: 0,
    body: undefined,
    status(code) {
      this.statusCode = code
      return this
    },
    json(body) {
      this.body = body
    },
  }
  return res
}

function makeEngine() {
  // The admin routers are typed for a production-mode engine; admin operations do not evaluate, so mode is moot.
  return new IamEngine({ adapter: new IamMemoryAdapter(), mode: 'production' })
}

/** A policy that fails validation: `rules` is required and is not a list here. */
const MALFORMED_POLICY = { id: 'p1', name: 'P', algorithm: 'deny-overrides', rules: 'not-a-list' }
/** A role that fails validation: `permissions` is required. */
const MALFORMED_ROLE = { id: 'r1', name: 'R' }
/** The same documents, well formed, so a 400 is not a blanket refusal. */
const VALID_POLICY = { id: 'p1', name: 'P', algorithm: 'deny-overrides', rules: [] }
const VALID_ROLE = { id: 'r1', name: 'R', permissions: [] }

describe('IamError for a validation failure', () => {
  it('is an Error, so every existing instanceof Error check still holds', () => {
    const err = new IamError('IAM_VALIDATION_FAILED', { kind: 'policy', issues: ['E_X at "rules"'] })
    expect(err).toBeInstanceOf(Error)
    expect(err.message).toBe('IAM_VALIDATION_FAILED')
  })

  it('carries which document failed and why', () => {
    const err = new IamError('IAM_VALIDATION_FAILED', { kind: 'role', issues: ['E_A', 'E_B'] })
    if (!hasIamErrorCode(err, 'IAM_VALIDATION_FAILED')) return expect.unreachable()
    expect(err.meta.kind).toBe('role')
    expect(err.meta.issues).toEqual(['E_A', 'E_B'])
  })

  it('is recognised by code even across a duplicated copy of the class', () => {
    // A duplicated copy of the package has a distinct class, so `instanceof` fails where the code check does not.
    class Impostor extends Error {
      code = 'IAM_VALIDATION_FAILED'
      meta = { kind: 'policy', issues: ['E_X'] }
    }
    expect(hasIamErrorCode(new Impostor(), 'IAM_VALIDATION_FAILED')).toBe(true)
    expect(hasIamErrorCode(new Error('boom'), 'IAM_VALIDATION_FAILED')).toBe(false)
    expect(hasIamErrorCode('IAM_VALIDATION_FAILED', 'IAM_VALIDATION_FAILED')).toBe(false)
    expect(hasIamErrorCode(null, 'IAM_VALIDATION_FAILED')).toBe(false)
  })
})

describe('the engine rejects a malformed document with a typed error', () => {
  it('savePolicy', async () => {
    const engine = makeEngine()
    const err = await engine.admin.savePolicy(MALFORMED_POLICY as never).catch((e: unknown) => e)
    expect(hasIamErrorCode(err, 'IAM_VALIDATION_FAILED')).toBe(true)
  })

  it('saveRole', async () => {
    const engine = makeEngine()
    const err = await engine.admin.saveRole(MALFORMED_ROLE as never).catch((e: unknown) => e)
    expect(hasIamErrorCode(err, 'IAM_VALIDATION_FAILED')).toBe(true)
  })

  it('names the kind so a router can say which document was wrong', async () => {
    const engine = makeEngine()
    const err = await engine.admin.savePolicy(MALFORMED_POLICY as never).catch((e: unknown) => e)
    expect(hasIamErrorCode(err, 'IAM_VALIDATION_FAILED') && err.meta.kind).toBe('policy')
  })
})

describe('express admin router: malformed body answers 400, not 500', () => {
  const mount = (onError?: () => void) => {
    const handlers: Record<string, (req: never, res: never) => Promise<void> | void> = {}
    const record = (k: string) => (p: string, h: (req: never, res: never) => Promise<void> | void) => {
      handlers[`${k} ${p}`] = h
    }
    const router = {
      get: vi.fn(record('GET')),
      put: vi.fn(record('PUT')),
      post: vi.fn(record('POST')),
      delete: vi.fn(record('DELETE')),
    }
    const opts = { authorize: () => true, csrfCheck: false as const, ...(onError ? { onError } : {}) }
    iamAdminRouter(makeEngine(), opts)(() => router as never)
    return handlers
  }

  it('PUT /policies with a malformed body is 400', async () => {
    const res = makeRes()
    await mount()['PUT /policies']!({ body: MALFORMED_POLICY } as never, res as never)
    expect(res.statusCode).toBe(400)
  })

  it('PUT /roles with a malformed body is 400', async () => {
    const res = makeRes()
    await mount()['PUT /roles']!({ body: MALFORMED_ROLE } as never, res as never)
    expect(res.statusCode).toBe(400)
  })

  it('the 400 names the document and lists the validator issues', async () => {
    const res = makeRes()
    await mount()['PUT /policies']!({ body: MALFORMED_POLICY } as never, res as never)
    const body = res.body
    expect(body).toMatchObject({ error: 'Invalid policy' })
    expect(Array.isArray((body as { issues: unknown }).issues)).toBe(true)
    expect((body as { issues: string[] }).issues.length).toBeGreaterThan(0)
  })

  it('does not route a client error through onError', async () => {
    const onError = vi.fn()
    const res = makeRes()
    await mount(onError)['PUT /policies']!({ body: MALFORMED_POLICY } as never, res as never)
    expect(onError).not.toHaveBeenCalled()
  })

  it('a well-formed body is still accepted, so 400 is not a blanket refusal', async () => {
    const res = makeRes()
    await mount()['PUT /policies']!({ body: VALID_POLICY } as never, res as never)
    expect(res.body).toEqual({ ok: true })
    expect(res.statusCode).toBe(0)
  })

  it('a genuine server fault is still a 500', async () => {
    // Not a validation failure: the adapter itself breaks.
    const engine = makeEngine()
    vi.spyOn(engine.admin, 'savePolicy').mockRejectedValue(new Error('disk on fire'))
    const handlers: Record<string, (req: never, res: never) => Promise<void> | void> = {}
    const record = (k: string) => (p: string, h: (req: never, res: never) => Promise<void> | void) => {
      handlers[`${k} ${p}`] = h
    }
    const router = {
      get: vi.fn(record('GET')),
      put: vi.fn(record('PUT')),
      post: vi.fn(record('POST')),
      delete: vi.fn(record('DELETE')),
    }
    iamAdminRouter(engine, { authorize: () => true, csrfCheck: false })(() => router as never)
    const res = makeRes()
    await handlers['PUT /policies']!({ body: VALID_POLICY } as never, res as never)
    expect(res.statusCode).toBe(500)
  })
})

describe('next admin handlers: malformed body answers 400, not 500', () => {
  const req = (body: unknown) =>
    new Request('https://x.test/admin/policies', {
      method: 'PUT',
      headers: { 'content-type': 'application/json', 'sec-fetch-site': 'same-origin' },
      body: JSON.stringify(body),
    })

  it('savePolicy with a malformed body is 400', async () => {
    const h = createIamAdminHandlers(makeEngine(), { authorize: () => true, csrfCheck: false })
    const res = await h.savePolicy(req(MALFORMED_POLICY), { params: {} })
    expect(res.status).toBe(400)
    await expect(res.json()).resolves.toMatchObject({ error: 'Invalid policy' })
  })

  it('saveRole with a malformed body is 400', async () => {
    const h = createIamAdminHandlers(makeEngine(), { authorize: () => true, csrfCheck: false })
    const res = await h.saveRole(req(MALFORMED_ROLE), { params: {} })
    expect(res.status).toBe(400)
  })

  it('a well-formed body still succeeds', async () => {
    const h = createIamAdminHandlers(makeEngine(), { authorize: () => true, csrfCheck: false })
    const res = await h.savePolicy(req(VALID_POLICY), { params: {} })
    expect(res.status).toBe(200)
  })
})

describe('hono admin router: malformed body answers 400, not 500', () => {
  type Handler = (c: unknown) => Promise<Response> | Response

  const mount = () => {
    const handlers: Record<string, Handler> = {}
    const record = (k: string) => (p: string, h: Handler) => {
      handlers[`${k} ${p}`] = h
    }
    const router = {
      get: vi.fn(record('GET')),
      put: vi.fn(record('PUT')),
      post: vi.fn(record('POST')),
      delete: vi.fn(record('DELETE')),
    }
    iamBindAdminRouter(router, makeEngine(), { authorize: () => true, csrfCheck: false })
    return handlers
  }

  const ctx = (body: unknown) => ({
    req: { param: () => undefined, json: async () => body, method: 'PUT', path: '/policies' },
    json: (data: unknown, status?: number) => ({ data, status: status ?? 200 }) as unknown as Response,
  })

  it('PUT /policies with a malformed body is 400', async () => {
    const res = (await mount()['PUT /policies']!(ctx(MALFORMED_POLICY))) as unknown as {
      status: number
      data: { error: string; issues: string[] }
    }
    expect(res.status).toBe(400)
    expect(res.data.error).toBe('Invalid policy')
    expect(res.data.issues.length).toBeGreaterThan(0)
  })

  it('PUT /roles with a malformed body is 400', async () => {
    const res = (await mount()['PUT /roles']!(ctx(MALFORMED_ROLE))) as unknown as { status: number }
    expect(res.status).toBe(400)
  })

  it('a well-formed body still succeeds', async () => {
    const res = (await mount()['PUT /policies']!(ctx(VALID_POLICY))) as unknown as { status: number }
    expect(res.status).toBe(200)
  })
})
