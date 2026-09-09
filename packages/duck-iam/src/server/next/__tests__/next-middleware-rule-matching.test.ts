import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../../core/engine'
import type { AccessControl } from '../../../core/types'
import { createIamNextMiddleware } from '../index'

/**
 * A string `pattern` is a **prefix**, not a substring. Nothing pinned that:
 * changing `path.startsWith(r.pattern)` to `path.includes(r.pattern)` passed
 * every test in the package, and the two disagree in the direction that
 * matters.
 *
 * `rules.find` takes the *first* match, so under `includes` a path is
 * authorized against whichever rule happens to appear as a substring first.
 * With the ordinary rule list below, `/admin/public-report` matches the
 * `/public` rule - so an admin route is checked as `resource: 'public'`, which
 * every subject can read. That is not a near-miss; it is the whole point of
 * having separate rules.
 *
 * The other direction is a pass-through: `/notes/admin-draft` matches no rule
 * as a prefix, and "no rule matched" is `return null`, so the request goes on
 * unauthorized. That is the documented behaviour - a rule list is opt-in - but
 * it is only correct because matching is anchored, so it is pinned here beside
 * the escalation rather than left implicit.
 */
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

    // Denied, because `reader` cannot read `admin`. Under substring matching
    // this returned null (allowed through) after checking `public`, which the
    // subject can read.
    expect(res?.status).toBe(403)
    expect(can).toHaveBeenCalledTimes(1)
    expect(can.mock.calls[0]?.[2]).toMatchObject({ type: 'admin' })
  })

  it('the resource checked is decided by the prefix, not by which pattern appears first', async () => {
    // The same claim stated as an absolute rather than through the verdict:
    // a verdict-only assertion is satisfied by any denial, including a wrong one.
    const { can, mw } = makeMiddleware()
    await mw(new Request('https://example.com/admin/public/public/public'))
    expect(can.mock.calls[0]?.[2]).toMatchObject({ type: 'admin' })
  })

  it('a path that merely contains a pattern mid-string matches no rule', async () => {
    const { can, mw } = makeMiddleware()
    const res = await mw(new Request('https://example.com/notes/admin-draft'))

    // No rule, so no opinion: the middleware passes the request on. Correct
    // only because matching is anchored - under `includes` this would have been
    // checked as `admin` instead.
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
