import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../../core/engine'
import type { AccessControl } from '../../../core/types'
import { createIamNextMiddleware } from '../index'

/**
 * `iamNormalizePathname` decodes exactly once. A path the framework decodes a
 * second time then names a different route than the one the middleware matched
 * its rules against - and "no rule matched" is `return null`, which passes the
 * request through with no authorization call at all.
 */
type Action = 'read'
type ResourceType = 'admin' | 'posts'
type RoleId = 'staff'

const staff: AccessControl.IRole<Action, ResourceType, RoleId> = {
  id: 'staff',
  name: 'Staff',
  permissions: [
    { action: 'read', resource: 'admin' },
    { action: 'read', resource: 'posts' },
  ],
}

function makeMiddleware() {
  const engine = new IamEngine<Action, ResourceType, RoleId>({
    adapter: new IamMemoryAdapter<Action, ResourceType, RoleId>({
      assignments: { u1: ['staff'] },
      roles: [staff],
    }),
    cacheTTL: 0,
  })
  const can = vi.spyOn(engine, 'can')
  const mw = createIamNextMiddleware<Action, ResourceType, RoleId>(engine, {
    getUserId: () => 'u1',
    rules: [
      { action: 'read', pattern: '/admin', resource: 'admin' },
      { action: 'read', pattern: '/posts', resource: 'posts' },
    ],
  })
  return { can, mw }
}

describe('next middleware: a path with encoding residue', () => {
  // `/posts/%252e%252e/admin` decodes once to `/posts/%2e%2e/admin`, matches
  // the `/posts` rule, and was authorized as `posts` - while a second decode
  // routes it to `/admin`.
  it('refuses rather than authorizing it against the rule for another route', async () => {
    const { can, mw } = makeMiddleware()
    const res = await mw(new Request('https://example.com/posts/%252e%252e/admin'))
    expect(res?.status).toBe(403)
    expect(can).not.toHaveBeenCalled()
  })

  // `/%2561dmin` decodes once to `/%61dmin`, which matches no rule at all, so
  // the middleware returned null and the request was never checked.
  it('refuses rather than passing an unmatched path through unchecked', async () => {
    const { can, mw } = makeMiddleware()
    const res = await mw(new Request('https://example.com/%2561dmin'))
    expect(res?.status).toBe(403)
    expect(can).not.toHaveBeenCalled()
  })

  // Controls: the same user, the same rules, paths with no residue. Without
  // these the assertions above would also pass on a middleware that refused
  // every request.
  it.each(['https://example.com/admin', 'https://example.com/posts/42', 'https://example.com//admin'])(
    'still authorizes %s normally',
    async (url) => {
      const { can, mw } = makeMiddleware()
      expect(await mw(new Request(url))).toBeNull()
      expect(can).toHaveBeenCalledOnce()
    },
  )

  // A single-decode path is still normalized, not refused: `%61dmin` is one
  // decode from `admin` and must be matched by the `/admin` rule.
  it('normalizes a singly-encoded path instead of refusing it', async () => {
    const { can, mw } = makeMiddleware()
    expect(await mw(new Request('https://example.com/%61dmin'))).toBeNull()
    expect(can.mock.calls[0]?.[2]).toMatchObject({ type: 'admin' })
  })
})
