import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../../core/engine/engine'
import { iamAdminRouter } from '../../express'
import { iamBindAdminRouter } from '../../hono'
import { createIamAdminOperations } from '../../nest'
import { createIamAdminHandlers } from '../../next'
import { iamAuditIdOf } from '../index'

// The audit `targetId` of `PUT /policies` and `PUT /roles` is read from the body before validation, so all four
// adapters must route it through `iamAuditIdOf` and record `undefined` for anything but a non-empty string.

const HOSTILE: readonly (readonly [string, unknown])[] = [
  ['a number', 42],
  ['a boolean', true],
  ['null', null],
  ['an array', ['a', 'b']],
  ['an empty string', ''],
  // SECURITY: an attacker-chosen `toString` is how a permissive audit field becomes log injection at the sink.
  ['an object', { toString: () => 'pwn' }],
]

const bodyWith = (id: unknown) => ({ algorithm: 'deny-overrides', id, name: 'P', rules: [] })
/** The same document with a usable id, so `undefined` is not simply always the answer. */
const GOOD = bodyWith('p1')

const makeEngine = () => new IamEngine({ adapter: new IamMemoryAdapter(), mode: 'production' })
const makeRes = () => ({
  body: undefined as unknown,
  json(b: unknown) {
    this.body = b
  },
  status() {
    return this
  },
})
const settle = () => new Promise((r) => setTimeout(r, 0))

/** Each adapter, reduced to "PUT this body, tell me the audit `targetId`". */
const ADAPTERS: readonly (readonly [string, (body: unknown) => Promise<unknown>])[] = [
  [
    'express',
    async (body) => {
      const handlers: Record<string, (req: never, res: never) => Promise<void> | void> = {}
      const record = (k: string) => (p: string, h: (req: never, res: never) => Promise<void> | void) => {
        handlers[`${k} ${p}`] = h
      }
      const router = {
        delete: vi.fn(record('DELETE')),
        get: vi.fn(record('GET')),
        post: vi.fn(record('POST')),
        put: vi.fn(record('PUT')),
      }
      const events: { targetId?: unknown }[] = []
      iamAdminRouter(makeEngine(), {
        authorize: () => 'admin-1',
        onAdminMutation: (e) => {
          events.push(e)
        },
        onError: () => undefined,
      })(() => router as never)
      await handlers['PUT /policies']?.({ body, method: 'PUT', path: '/policies' } as never, makeRes() as never)
      await settle()
      return events[0]?.targetId
    },
  ],
  [
    'hono',
    async (body) => {
      const handlers: Record<string, (c: never) => Promise<unknown>> = {}
      const record = (k: string) => (p: string, h: (c: never) => Promise<unknown>) => {
        handlers[`${k} ${p}`] = h
      }
      const router = {
        delete: vi.fn(record('DELETE')),
        get: vi.fn(record('GET')),
        post: vi.fn(record('POST')),
        put: vi.fn(record('PUT')),
      }
      const events: { targetId?: unknown }[] = []
      iamBindAdminRouter(router as never, makeEngine(), {
        authorize: () => 'admin-1',
        csrfCheck: false,
        onAdminMutation: (e) => {
          events.push(e)
        },
        // Hono and next require a real `Response`; these tests read only the audit event.
        onError: () => new Response(null, { status: 500 }),
      })
      await handlers['PUT /policies']?.({
        json: (data: unknown) => data as never,
        req: { json: async () => body, method: 'PUT', param: () => undefined, path: '/policies' },
      } as never)
      await settle()
      return events[0]?.targetId
    },
  ],
  [
    'next',
    async (body) => {
      const events: { targetId?: unknown }[] = []
      const h = createIamAdminHandlers(makeEngine(), {
        authorize: () => 'admin-1',
        onAdminMutation: (e) => {
          events.push(e)
        },
        onError: () => new Response(null, { status: 500 }),
      })
      await h.savePolicy(
        { headers: new Headers(), json: async () => body, method: 'PUT', url: 'http://x/policies' } as never,
        { params: {} } as never,
      )
      await settle()
      return events[0]?.targetId
    },
  ],
  [
    'nest',
    async (body) => {
      const events: { targetId?: unknown }[] = []
      const ops = createIamAdminOperations(makeEngine(), {
        authorize: () => 'admin-1',
        onAdminMutation: (e) => {
          events.push(e)
        },
      })
      await ops
        .savePolicy({ headers: {}, method: 'PUT', url: '/policies' } as never, body as never)
        .catch(() => undefined)
      await settle()
      return events[0]?.targetId
    },
  ],
]

describe('admin audit targetId is read, not asserted', () => {
  it('CONTROL: every adapter records a usable id, so `undefined` is not the only answer', async () => {
    const seen: Record<string, unknown> = {}
    for (const [name, put] of ADAPTERS) seen[name] = await put(GOOD)
    expect(seen).toEqual({ express: 'p1', hono: 'p1', nest: 'p1', next: 'p1' })
  })

  it('CONTROL: the shared reader is the thing the adapters agree with', () => {
    expect(iamAuditIdOf(GOOD)).toBe('p1')
    for (const [, id] of HOSTILE) expect(iamAuditIdOf(bodyWith(id))).toBeUndefined()
  })

  for (const [label, id] of HOSTILE) {
    it(`no adapter writes ${label} into targetId`, async () => {
      const seen: Record<string, unknown> = {}
      for (const [name, put] of ADAPTERS) seen[name] = await put(bodyWith(id))
      expect(seen).toEqual({ express: undefined, hono: undefined, nest: undefined, next: undefined })
    })
  }

  it('a body that is not an object at all has no target', async () => {
    for (const [, put] of ADAPTERS) expect(await put('just a string')).toBeUndefined()
  })
})
