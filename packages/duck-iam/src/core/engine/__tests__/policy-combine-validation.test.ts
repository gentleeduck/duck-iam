import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

// Both engines treat any value other than `'and'` / `'allow-overrides'` as the most permissive `first-applicable`,
// so an unknown `policyCombine` must throw rather than silently turn a deny into an allow.
type Action = 'read'
type ResourceType = 'post'
type RoleId = 'reader'

const allowPost: AccessControl.IPolicy<Action, ResourceType, RoleId> = {
  algorithm: 'first-match',
  id: 'p-allow',
  name: 'allow',
  rules: [{ actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r-a', priority: 1, resources: ['post'] }],
}

const denyPost: AccessControl.IPolicy<Action, ResourceType, RoleId> = {
  algorithm: 'deny-overrides',
  id: 'p-deny',
  name: 'deny',
  rules: [{ actions: ['read'], conditions: { all: [] }, effect: 'deny', id: 'r-d', priority: 1, resources: ['post'] }],
}

function build(policyCombine: unknown): IamEngine<Action, ResourceType, RoleId, string, 'development'> {
  return new IamEngine<Action, ResourceType, RoleId, string, 'development'>({
    adapter: new IamMemoryAdapter<Action, ResourceType, RoleId>({
      assignments: { u1: ['reader'] },
      policies: [allowPost, denyPost],
      roles: [{ id: 'reader', name: 'Reader', permissions: [] }],
    }),
    cacheTTL: 0,
    // Pinned: production rejects 'first-applicable', which has its own test below.
    mode: 'development',
    // TypeScript already refuses these; only JS or config-driven callers reach the runtime guard.
    ...JSON.parse(JSON.stringify({ policyCombine })),
  })
}

describe('policyCombine validation', () => {
  it.each(['or', 'OR', 'GARBAGE', '', 'deny-overrides'])('rejects %o at construction', (value) => {
    expect(() => build(value)).toThrow(/unknown policyCombine/)
  })

  it('names the accepted values in the message', () => {
    expect(() => build('or')).toThrow(/and, allow-overrides, first-applicable/)
  })

  // Controls: the real values construct and the deny still wins, so the rejections are not a refuse-everything engine.
  it.each(['and', 'allow-overrides', 'first-applicable'] as const)('accepts %s', (value) => {
    expect(() => build(value)).not.toThrow()
  })

  // The production fast path cannot represent first-applicable, so a config without `mode` throws at construction.
  it("rejects 'first-applicable' under the default (production) mode", () => {
    expect(
      () =>
        new IamEngine<Action, ResourceType, RoleId>({
          adapter: new IamMemoryAdapter<Action, ResourceType, RoleId>({
            assignments: { u1: ['reader'] },
            policies: [allowPost, denyPost],
            roles: [{ id: 'reader', name: 'Reader', permissions: [] }],
          }),
          cacheTTL: 0,
          policyCombine: 'first-applicable',
        }),
    ).toThrow(/requires mode 'development'/)
  })

  it('control: the deny is still enforced under the default combine', async () => {
    const engine = build('and')
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' })).toBe(false)
  })
})
