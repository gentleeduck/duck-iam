import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../../core/engine'
import type { AccessControl } from '../../../core/types'
import { createIamNextMiddleware } from '../index'

// SECURITY: `iamNormalizePathname` decodes once, so a path with double-encoding residue must be refused, not matched
// against another route's rule or passed through unmatched.
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
  // Decodes once to `/posts/%2e%2e/admin`, which matches `/posts`, while a second decode routes it to `/admin`.
  it('refuses rather than authorizing it against the rule for another route', async () => {
    const { can, mw } = makeMiddleware()
    const res = await mw(new Request('https://example.com/posts/%252e%252e/admin'))
    expect(res?.status).toBe(403)
    expect(can).not.toHaveBeenCalled()
  })

  // `/%2561dmin` decodes once to `/%61dmin`, which matches no rule and would pass through unchecked.
  it('refuses rather than passing an unmatched path through unchecked', async () => {
    const { can, mw } = makeMiddleware()
    const res = await mw(new Request('https://example.com/%2561dmin'))
    expect(res?.status).toBe(403)
    expect(can).not.toHaveBeenCalled()
  })

  // Controls: paths with no residue, so a middleware that refused everything would fail.
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
