import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { _resetDevelopmentModeWarning, IamEngine } from '../engine'

// `defaultEffect: 'allow'` warns unconditionally "so an operator grep'ing logs for fail-open configurations always
// finds it". Development mode is the other one, and the worse one: a deny still answers `false` under fail-open,
// but here `check()` and `authorize()` answer a decision object, which is truthy for a deny.

const POST = { attributes: {}, id: 'p1', type: 'post' }
const ROLES: AccessControl.IRole[] = [{ id: 'reader', name: 'R', permissions: [{ action: 'read', resource: 'post' }] }]

const adapter = () => new IamMemoryAdapter({ assignments: { u1: ['reader'] }, policies: [], roles: ROLES })

/** Builds an engine with console.warn captured, returning the warnings that construction produced. */
function built<T>(make: () => T): { warnings: string[]; value: T } {
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
  try {
    const value = make()
    return { value, warnings: warn.mock.calls.map((args) => args.map(String).join(' ')) }
  } finally {
    warn.mockRestore()
  }
}

beforeEach(() => {
  _resetDevelopmentModeWarning()
})

describe('development mode announces itself', () => {
  it('names the consequence, not just the mode', () => {
    const { warnings } = built(() => new IamEngine({ adapter: adapter(), mode: 'development' }))

    expect(warnings).toHaveLength(1)
    expect(warnings[0]).toContain("mode: 'development'")
    expect(warnings[0]).toContain('truthy even for a deny')
    expect(warnings[0]).toContain('explain()')
  })

  it('is silent in production', () => {
    const { warnings } = built(() => new IamEngine({ adapter: adapter(), mode: 'production' }))

    expect(warnings).toEqual([])
  })

  it('says it once per process, which is what a log search needs', () => {
    built(() => new IamEngine({ adapter: adapter(), mode: 'development' }))
    const second = built(() => new IamEngine({ adapter: adapter(), mode: 'development' }))

    expect(second.warnings).toEqual([])
  })

  it('warns about exactly what a deny then reads as', async () => {
    const engine = built(() => new IamEngine({ adapter: adapter(), mode: 'development' })).value

    const viaCheck = await engine.check('u1', 'delete', POST)
    const viaAuthorize = await engine.authorize({
      action: 'delete',
      resource: POST,
      subject: { attributes: {}, id: 'u1', roles: [] },
    })

    expect({
      authorizeTruthy: Boolean(viaAuthorize),
      canTruthy: Boolean(await engine.can('u1', 'delete', POST)),
      checkAllowed: viaCheck.allowed,
      checkTruthy: Boolean(viaCheck),
    }).toEqual({ authorizeTruthy: true, canTruthy: false, checkAllowed: false, checkTruthy: true })
  })

  it('does not describe production, where a deny is falsy through every entry point', async () => {
    const engine = built(() => new IamEngine({ adapter: adapter(), mode: 'production' })).value

    expect({
      authorize: await engine.authorize({
        action: 'delete',
        resource: POST,
        subject: { attributes: {}, id: 'u1', roles: [] },
      }),
      can: await engine.can('u1', 'delete', POST),
      check: await engine.check('u1', 'delete', POST),
    }).toEqual({ authorize: false, can: false, check: false })
  })

  it('fires for an engine pushed into development by its policyCombine', () => {
    // `first-applicable` is refused in production, so choosing it chooses the truthy-deny mode with it.
    const { warnings } = built(
      () => new IamEngine({ adapter: adapter(), mode: 'development', policyCombine: 'first-applicable' }),
    )

    expect(warnings).toHaveLength(1)
  })
})
