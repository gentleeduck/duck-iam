import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

/**
 * Both engines branch on `'and'` and `'allow-overrides'` and treat everything
 * else as `first-applicable` - the most permissive of the three. Nothing
 * validated the config, so a typo, or a value read from a config file rather
 * than written in TypeScript, silently dropped deny-overrides semantics. A
 * guide in this repo recommended `policyCombine: 'or'`, which turned a deny
 * into an allow for anyone who followed it.
 */
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

function build(policyCombine: unknown): IamEngine<Action, ResourceType, RoleId> {
  return new IamEngine<Action, ResourceType, RoleId>({
    adapter: new IamMemoryAdapter<Action, ResourceType, RoleId>({
      assignments: { u1: ['reader'] },
      policies: [allowPost, denyPost],
      roles: [{ id: 'reader', name: 'Reader', permissions: [] }],
    }),
    cacheTTL: 0,
    // The guard is a runtime one: TypeScript already refuses these, which is
    // exactly why only a JS or config-driven caller ever reached the fallback.
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

  // Controls: the three real values still construct, and the deny still wins
  // under `and` - so the assertions above are not passing on an engine that
  // refuses everything.
  it.each(['and', 'allow-overrides', 'first-applicable'] as const)('accepts %s', (value) => {
    expect(() => build(value)).not.toThrow()
  })

  it('control: the deny is still enforced under the default combine', async () => {
    const engine = build('and')
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' })).toBe(false)
  })
})
