import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { definePolicy } from '../../../core/builder/policy'
import { defineRole } from '../../../core/builder/role'
import { defineRule } from '../../../core/builder/rule'
import { IamEngine } from '../../../core/engine'
import { iamAccessMiddleware } from '../index'

/**
 * The bypass this closes, through the real middleware rather than its parts.
 *
 * `iamAccessMiddleware`'s default `getResource` is `iamDefaultResource(req.path)`,
 * which refuses to resolve a path that this layer and the router downstream
 * would read differently and returns the `unknown` sentinel instead. The
 * sentinel was an ordinary string, so an `.of('*')` rule matched it: a subject
 * with a wildcard grant - an admin - sailed through the guard on
 * `/posts/../admin/secret`, and express then handed the raw target to whichever
 * route matched it. Authorized as one resource, served as another.
 *
 * The wildcard role is the point of the fixture. With a role that names its
 * resources the sentinel really did match nothing, which is why the hole stayed
 * open: it is invisible in exactly the test setups people write.
 */
async function wildcardEngine() {
  const adapter = new IamMemoryAdapter<string, string, string, string>()
  await adapter.saveRole(defineRole<'admin', string, string>('admin').name('Admin').grant('*', '*').build())
  await adapter.assignRole('admin-1', 'admin')
  await adapter.savePolicy(
    definePolicy<string, string>('wildcard')
      .name('Admins may do anything')
      .addRule(defineRule<string, string>('anything').allow().on('*').of('*').build())
      .build(),
  )
  return new IamEngine<string, string, string, string>({ adapter, cacheTTL: 0 })
}

interface MockRes {
  statusCode: number
  body: unknown
  status(code: number): MockRes
  json(body: unknown): void
}

function makeRes(): MockRes {
  const res: MockRes = {
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

async function run(path: string, method = 'GET') {
  const engine = await wildcardEngine()
  const mw = iamAccessMiddleware(engine, { getUserId: () => 'admin-1' })
  const res = makeRes()
  const next = vi.fn()
  await mw({ method, path } as unknown as Parameters<typeof mw>[0], res as unknown as Parameters<typeof mw>[1], next)
  return { called: next.mock.calls.length > 0, status: res.statusCode }
}

describe('iamAccessMiddleware refuses a path it cannot map, even for a wildcard admin', () => {
  it.each([
    ['/posts/../admin/secret'],
    ['/posts/%2e%2e/admin/secret'],
    ['/posts%5C..%5Cadmin'],
    ['/posts\\..\\admin'],
    ['/./admin'],
  ])('denies %s', async (path) => {
    const { called, status } = await run(path)
    expect(called).toBe(false)
    expect(status).toBe(403)
  })

  it('denies a method it cannot map to an action', async () => {
    const { called, status } = await run('/posts/1', 'PROPFIND')
    expect(called).toBe(false)
    expect(status).toBe(403)
  })

  it('still lets the same admin through on an ordinary request', async () => {
    const { called, status } = await run('/posts/1')
    expect(called).toBe(true)
    expect(status).toBe(0)
  })

  it.each([['GET'], ['POST'], ['PUT'], ['PATCH'], ['DELETE']])('still maps %s for an ordinary path', async (method) => {
    const { called } = await run('/posts/1', method)
    expect(called).toBe(true)
  })
})
