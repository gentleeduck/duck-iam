import { describe, expect, it } from 'vitest'
import type { AccessControl, IamRequest } from '../../types'
import { combiners, policyApplies, policyTargetsActionResource, ruleApplies, ruleTargetsMatch } from '../evaluate.libs'

function makeReq(overrides: Partial<IamRequest.IAccessRequest> = {}): IamRequest.IAccessRequest {
  return {
    subject: { id: 'user-1', roles: ['editor'], attributes: { level: 5 } },
    action: 'read',
    resource: { type: 'post', id: 'post-1', attributes: { ownerId: 'user-1' } },
    ...overrides,
  }
}

function makeRule(overrides: Partial<AccessControl.IRule> = {}): AccessControl.IRule {
  return {
    id: 'r1',
    effect: 'allow',
    priority: 10,
    actions: ['read'],
    resources: ['post'],
    conditions: { all: [] },
    ...overrides,
  }
}

describe('ruleTargetsMatch()', () => {
  it('matches on exact action + resource', () => {
    expect(ruleTargetsMatch(makeRule(), makeReq())).toBe(true)
  })

  it('rejects a non-matching action without looking at resources', () => {
    expect(ruleTargetsMatch(makeRule({ actions: ['write'] }), makeReq())).toBe(false)
  })

  it('rejects a non-matching resource', () => {
    expect(ruleTargetsMatch(makeRule({ resources: ['comment'] }), makeReq())).toBe(false)
  })

  it('honours wildcard action and resource patterns', () => {
    expect(ruleTargetsMatch(makeRule({ actions: ['*'] }), makeReq())).toBe(true)
    expect(ruleTargetsMatch(makeRule({ resources: ['*'] }), makeReq())).toBe(true)
    expect(ruleTargetsMatch(makeRule({ actions: ['posts:*'] }), makeReq({ action: 'posts:read' }))).toBe(true)
  })

  it('routes through hierarchical matching when either side has a dot', () => {
    const req = makeReq({ resource: { attributes: {}, id: 'x', type: 'org.team.post' } })
    expect(ruleTargetsMatch(makeRule({ resources: ['org.*'] }), req)).toBe(true)
    // Bare parent must NOT match a dot-child.
    expect(ruleTargetsMatch(makeRule({ resources: ['org'] }), req)).toBe(false)
  })

  it('ignores conditions entirely - shape only', () => {
    const rule = makeRule({ conditions: { all: [{ field: 'subject.id', operator: 'eq', value: 'nobody' }] } })
    expect(ruleTargetsMatch(rule, makeReq())).toBe(true)
  })
})

describe('ruleApplies()', () => {
  it('is ruleTargetsMatch AND the condition tree', () => {
    const passing = makeRule({ conditions: { all: [{ field: 'subject.id', operator: 'eq', value: 'user-1' }] } })
    const failing = makeRule({ conditions: { all: [{ field: 'subject.id', operator: 'eq', value: 'nobody' }] } })
    expect(ruleApplies(passing, makeReq())).toBe(true)
    expect(ruleApplies(failing, makeReq())).toBe(false)
  })

  it('short-circuits false when the shape does not match, whatever the conditions say', () => {
    const rule = makeRule({ actions: ['delete'], conditions: { all: [] } })
    expect(ruleApplies(rule, makeReq())).toBe(false)
  })

  it('threads a per-instance regex cache through to the operator', () => {
    const regex = new Map<string, RegExp>()
    const rule = makeRule({ conditions: { all: [{ field: 'subject.id', operator: 'matches', value: '^user-' }] } })
    expect(ruleApplies(rule, makeReq(), { regex })).toBe(true)
    expect(regex.has('^user-')).toBe(true)
  })
})

describe('policyTargetsActionResource()', () => {
  const targeted: AccessControl.IPolicy = {
    algorithm: 'deny-overrides',
    id: 'p',
    name: 'p',
    rules: [],
    targets: { actions: ['read'], resources: ['post'] },
  }

  it('an untargeted policy applies to everything', () => {
    expect(policyTargetsActionResource({ ...targeted, targets: undefined }, 'anything', 'anywhere')).toBe(true)
  })

  it('requires every declared dimension to match', () => {
    expect(policyTargetsActionResource(targeted, 'read', 'post')).toBe(true)
    expect(policyTargetsActionResource(targeted, 'write', 'post')).toBe(false)
    expect(policyTargetsActionResource(targeted, 'read', 'comment')).toBe(false)
  })

  it('an empty target array is treated as "unconstrained", not "matches nothing"', () => {
    const empty: AccessControl.IPolicy = { ...targeted, targets: { actions: [], resources: [] } }
    expect(policyTargetsActionResource(empty, 'anything', 'anywhere')).toBe(true)
  })

  it('ignores the roles dimension - that is policyApplies()', () => {
    const roleOnly: AccessControl.IPolicy = { ...targeted, targets: { roles: ['admin'] } }
    expect(policyTargetsActionResource(roleOnly, 'read', 'post')).toBe(true)
    expect(policyApplies(roleOnly, makeReq())).toBe(false)
    expect(policyApplies(roleOnly, makeReq({ subject: { attributes: {}, id: 'u', roles: ['admin'] } }))).toBe(true)
  })

  it('policyApplies treats a non-array subject.roles as no roles', () => {
    const roleOnly: AccessControl.IPolicy = { ...targeted, targets: { roles: ['admin'] } }
    const req = makeReq()
    const broken = { ...req, subject: { ...req.subject, roles: undefined as unknown as string[] } }
    expect(policyApplies(roleOnly, broken)).toBe(false)
  })
})

describe('combiners', () => {
  const allow = { effect: 'allow' as const, rule: makeRule({ id: 'a', priority: 1 }) }
  const deny = { effect: 'deny' as const, rule: makeRule({ effect: 'deny', id: 'd', priority: 2 }) }

  it('deny-overrides picks any deny before any allow', () => {
    expect(combiners['deny-overrides']([allow, deny], 'allow').effect).toBe('deny')
    expect(combiners['deny-overrides']([allow], 'deny').effect).toBe('allow')
  })

  it('allow-overrides picks any allow before any deny', () => {
    expect(combiners['allow-overrides']([deny, allow], 'deny').effect).toBe('allow')
    expect(combiners['allow-overrides']([deny], 'allow').effect).toBe('deny')
  })

  it('first-match and highest-priority pick the highest priority rule', () => {
    expect(combiners['first-match']([allow, deny], 'allow').rule?.id).toBe('d')
    expect(combiners['highest-priority']([allow, deny], 'allow').rule?.id).toBe('d')
  })

  it('first-match keeps source order on a priority tie', () => {
    const tie = { effect: 'deny' as const, rule: makeRule({ effect: 'deny', id: 'd-tie', priority: 1 }) }
    expect(combiners['first-match']([allow, tie], 'deny').rule?.id).toBe('a')
    expect(combiners['highest-priority']([allow, tie], 'deny').rule?.id).toBe('a')
  })

  it('every combiner falls back to the default effect with no matches and reports no rule', () => {
    for (const algo of ['deny-overrides', 'allow-overrides', 'first-match', 'highest-priority'] as const) {
      const res = combiners[algo]([], 'deny')
      expect(res.effect).toBe('deny')
      expect(res.rule).toBeUndefined()
      expect(combiners[algo]([], 'allow').effect).toBe('allow')
    }
  })
})
