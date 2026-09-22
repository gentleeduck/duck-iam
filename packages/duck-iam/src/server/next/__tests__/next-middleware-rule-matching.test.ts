import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../../core/engine'
import type { AccessControl } from '../../../core/types'
import { createIamNextMiddleware } from '../index'

// SECURITY: a string `pattern` is a prefix, not a substring. `rules.find` takes the first match, so substring
// matching would check `/admin/public-report` against the `/public` rule.
type Action = 'read'
type ResourceType = 'admin' | 'public'
type RoleId = 'reader'

/** Can read `public` and nothing else - the whole escalation turns on this. */
const reader: AccessControl.IRole<Action, ResourceType, RoleId> = {
  id: 'reader',
  name: 'Reader',
  permissions: [{ action: 'read', resource: 'public' }],
}

function makeMiddleware() {
  const engine = new IamEngine<Action, ResourceType, RoleId>({
    adapter: new IamMemoryAdapter<Action, ResourceType, RoleId>({
      assignments: { u1: ['reader'] },
      roles: [reader],
    }),
    cacheTTL: 0,
  })
  const can = vi.spyOn(engine, 'can')
  const mw = createIamNextMiddleware<Action, ResourceType, RoleId>(engine, {
    getUserId: () => 'u1',
    rules: [
      // `/public` is listed first, as the more permissive rule usually is.
      { action: 'read', pattern: '/public', resource: 'public' },
      { action: 'read', pattern: '/admin', resource: 'admin' },
    ],
  })
  return { can, mw }
}

describe('next middleware: a string rule pattern matches as a prefix', () => {
  it('an admin path containing another rule pattern is still checked as admin', async () => {
    const { can, mw } = makeMiddleware()
    const res = await mw(new Request('https://example.com/admin/public-report'))

    // Denied: `reader` cannot read `admin`. Substring matching would check `public` and let it through.
    expect(res?.status).toBe(403)
    expect(can).toHaveBeenCalledTimes(1)
    expect(can.mock.calls[0]?.[2]).toMatchObject({ type: 'admin' })
  })

  it('the resource checked is decided by the prefix, not by which pattern appears first', async () => {
    // Asserted on the resource, since any denial, even a wrong one, satisfies a verdict-only check.
    const { can, mw } = makeMiddleware()
    await mw(new Request('https://example.com/admin/public/public/public'))
    expect(can.mock.calls[0]?.[2]).toMatchObject({ type: 'admin' })
  })

  it('a path that merely contains a pattern mid-string matches no rule', async () => {
    const { can, mw } = makeMiddleware()
    const res = await mw(new Request('https://example.com/notes/admin-draft'))

    // No rule matched, so the request passes on; this is only correct because matching is anchored.
    expect(res).toBeNull()
    expect(can).not.toHaveBeenCalled()
  })

  it('the ordinary prefix cases still match - the control', async () => {
    const { can, mw } = makeMiddleware()
    expect(await mw(new Request('https://example.com/public/index'))).toBeNull()
    expect(can.mock.calls[0]?.[2]).toMatchObject({ type: 'public' })

    const res = await mw(new Request('https://example.com/admin'))
    expect(res?.status).toBe(403)
    expect(can.mock.calls[1]?.[2]).toMatchObject({ type: 'admin' })
  })
})
