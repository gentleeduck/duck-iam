import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../engine'
import type { AccessControl, IamRequest } from '../../types'
import { policyTargetsActionResource, ruleTargetsMatch } from '../evaluate.libs'

/** Pattern, resource type, and whether a rule declaring that pattern covers that type. */
const TABLE: { covers: boolean; pattern: string; type: string }[] = [
  { covers: true, pattern: '*', type: 'posts:comment.reply' },
  { covers: true, pattern: 'posts:*', type: 'posts:comment' },
  { covers: true, pattern: 'posts:*', type: 'posts:comment.reply' },
  { covers: true, pattern: 'posts:*', type: 'posts:a:b' },
  { covers: false, pattern: 'posts:*', type: 'posts.comment' },
  { covers: false, pattern: 'posts:*', type: 'postsx:comment' },
  { covers: true, pattern: 'docs.*', type: 'docs.internal' },
  { covers: true, pattern: 'docs.*', type: 'docs.internal.secret' },
  { covers: false, pattern: 'docs.*', type: 'docs' },
  { covers: false, pattern: 'docs.*', type: 'docs:internal' },
  { covers: false, pattern: 'docs', type: 'docs.internal' },
  { covers: true, pattern: 'docs', type: 'docs' },
]

const req = (type: string): IamRequest.IAccessRequest => ({
  action: 'read',
  resource: { attributes: {}, type },
  subject: { attributes: {}, id: 'u1', roles: [] },
})

function policyWith(resources: string[], effect: AccessControl.Effect): AccessControl.IPolicy {
  return {
    algorithm: 'deny-overrides',
    description: '',
    id: 'p',
    name: 'p',
    rules: [
      { actions: ['read'], conditions: { all: [] }, effect, id: 'r', priority: 100, resources },
      { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'baseline', priority: 1, resources: ['*'] },
    ],
    version: 1,
  }
}

/** A permission wide enough that only the policy decides, so the answer isolates resource matching. */
async function engineFor<TMode extends 'development' | 'production'>(
  resources: string[],
  mode: TMode,
): Promise<IamEngine<string, string, string, string, TMode>> {
  const adapter = new IamMemoryAdapter()
  await adapter.saveRole({
    description: '',
    id: 'reader',
    inherits: [],
    name: 'reader',
    permissions: [{ action: 'read', resource: '*' }],
  })
  await adapter.assignRole('u1', 'reader')
  await adapter.savePolicy(policyWith(resources, 'deny'))
  return new IamEngine({ adapter, cacheTTL: 0, mode })
}

describe('a resource pattern means the same thing everywhere', () => {
  it.each(TABLE)('rule level: $pattern covers $type -> $covers', ({ covers, pattern, type }) => {
    const rule: AccessControl.IRule = {
      actions: ['read'],
      conditions: { all: [] },
      effect: 'deny',
      id: 'r',
      priority: 1,
      resources: [pattern],
    }
    expect(ruleTargetsMatch(rule, req(type))).toBe(covers)
  })

  it.each(TABLE)('policy-target level agrees: $pattern covers $type -> $covers', ({ covers, pattern, type }) => {
    const policy: AccessControl.IPolicy = {
      algorithm: 'deny-overrides',
      description: '',
      id: 'p',
      name: 'p',
      rules: [],
      targets: { resources: [pattern] },
      version: 1,
    }
    expect(policyTargetsActionResource(policy, 'read', type)).toBe(covers)
  })

  it.each(TABLE)(
    'the deny fires in development: $pattern on $type -> denied $covers',
    async ({ covers, pattern, type }) => {
      const engine = await engineFor([pattern], 'development')
      expect(await engine.can('u1', 'read', { attributes: {}, type })).toBe(!covers)
    },
  )

  it.each(TABLE)(
    'the compiled table agrees: $pattern on $type -> denied $covers',
    async ({ covers, pattern, type }) => {
      const engine = await engineFor([pattern], 'production')
      expect(await engine.can('u1', 'read', { attributes: {}, type })).toBe(!covers)
    },
  )

  it('explain() reports the same resource match the verdict used', async () => {
    const engine = await engineFor(['posts:*'], 'development')
    const result = await engine.explain('u1', 'read', { attributes: {}, type: 'posts:comment.reply' })
    expect(result.decision.allowed).toBe(false)
    const trace = result.policies.flatMap((p) => p.rules).find((r) => r.ruleId === 'r')
    expect(trace?.resourceMatch).toBe(true)
  })

  it('a dot in the type no longer retires a colon-wildcard deny', async () => {
    const engine = await engineFor(['posts:*'], 'production')
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'posts:comment' })).toBe(false)
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'posts:comment.reply' })).toBe(false)
  })
})
