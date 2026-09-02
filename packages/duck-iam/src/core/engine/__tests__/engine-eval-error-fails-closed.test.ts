import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { MAX_REGEX_INPUT_LENGTH } from '../../conditions/conditions.libs'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

/**
 * End-to-end guard for the padded-header bypass: a deny rule that throws while
 * evaluating (oversized `matches` input) must not be skipped, in either mode.
 * Production routes through the compiled table, development through the
 * interpreter, so both need covering.
 */
type A = 'read'
type R = 'post'
type Ro = 'viewer'
type S = 'org-1'

const OVERSIZED = 'curl'.padEnd(MAX_REGEX_INPUT_LENGTH + 1, 'x')

const policies: AccessControl.IPolicy<A, R, Ro>[] = [
  {
    id: 'p-posts',
    name: 'posts',
    algorithm: 'deny-overrides',
    rules: [
      { id: 'r-allow', effect: 'allow', priority: 1, actions: ['read'], resources: ['post'], conditions: { all: [] } },
      {
        id: 'r-deny-bots',
        effect: 'deny',
        priority: 10,
        actions: ['read'],
        resources: ['post'],
        conditions: { all: [{ field: 'environment.userAgent', operator: 'matches', value: 'curl' }] },
      },
    ],
  },
]

function engineOf(mode: 'development' | 'production', failOpen = false) {
  const adapter = new IamMemoryAdapter<A, R, Ro, S>({ roles: [], assignments: {}, policies })
  return new IamEngine<A, R, Ro, S, typeof mode>({
    adapter,
    cacheTTL: 0,
    mode,
    ...(failOpen ? { allowFailOpen: true, defaultEffect: 'allow' as const } : {}),
  })
}

const post = { type: 'post' as const, attributes: {} }

describe.each(['development', 'production'] as const)('%s mode: padded user agent', (mode) => {
  it('control: a normal matching user agent is denied', async () => {
    expect(await engineOf(mode).can('u1', 'read', post, { userAgent: 'curl' })).toBe(false)
  })

  it('control: a non-matching user agent is allowed', async () => {
    expect(await engineOf(mode).can('u1', 'read', post, { userAgent: 'firefox' })).toBe(true)
  })

  it('padding the user agent past the regex cap does not buy an allow', async () => {
    expect(await engineOf(mode).can('u1', 'read', post, { userAgent: OVERSIZED })).toBe(false)
  })
})

/**
 * The discriminating case: on a fail-open engine, abstaining on the error
 * yields `allow`, so only a genuine fail-closed produces `false` here.
 */
describe.each(['development', 'production'] as const)('%s mode, fail-open engine', (mode) => {
  it('control: a non-matching user agent is allowed', async () => {
    expect(await engineOf(mode, true).can('u1', 'read', post, { userAgent: 'firefox' })).toBe(true)
  })

  it('padded user agent still denies rather than falling through to allow', async () => {
    expect(await engineOf(mode, true).can('u1', 'read', post, { userAgent: OVERSIZED })).toBe(false)
  })
})
