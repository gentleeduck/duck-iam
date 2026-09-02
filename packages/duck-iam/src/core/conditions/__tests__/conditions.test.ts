import { describe, expect, it } from 'vitest'
import type { AccessControl, IamRequest } from '../../types'
import { evalConditionGroup } from '../conditions'

function makeReq(overrides: Partial<IamRequest.IAccessRequest> = {}): IamRequest.IAccessRequest {
  return {
    subject: {
      id: 'user-1',
      roles: ['editor'],
      attributes: { department: 'engineering', level: 5 },
    },
    action: 'read',
    resource: {
      type: 'post',
      id: 'post-42',
      attributes: { ownerId: 'user-1', published: true, tags: ['tech', 'news'] },
    },
    ...overrides,
  }
}

describe('condition operators', () => {
  const req = makeReq()

  describe('eq / neq', () => {
    it('eq matches equal values', () => {
      expect(evalConditionGroup(req, { all: [{ field: 'action', operator: 'eq', value: 'read' }] })).toBe(true)
    })

    it('eq rejects unequal values', () => {
      expect(evalConditionGroup(req, { all: [{ field: 'action', operator: 'eq', value: 'write' }] })).toBe(false)
    })

    it('neq matches unequal values', () => {
      expect(evalConditionGroup(req, { all: [{ field: 'action', operator: 'neq', value: 'write' }] })).toBe(true)
    })
  })

  describe('gt / gte / lt / lte', () => {
    it('gt compares numbers', () => {
      expect(evalConditionGroup(req, { all: [{ field: 'subject.attributes.level', operator: 'gt', value: 3 }] })).toBe(
        true,
      )
      expect(evalConditionGroup(req, { all: [{ field: 'subject.attributes.level', operator: 'gt', value: 5 }] })).toBe(
        false,
      )
    })

    it('gte includes equal', () => {
      expect(evalConditionGroup(req, { all: [{ field: 'subject.attributes.level', operator: 'gte', value: 5 }] })).toBe(
        true,
      )
    })

    it('lt compares numbers', () => {
      expect(evalConditionGroup(req, { all: [{ field: 'subject.attributes.level', operator: 'lt', value: 10 }] })).toBe(
        true,
      )
      expect(evalConditionGroup(req, { all: [{ field: 'subject.attributes.level', operator: 'lt', value: 5 }] })).toBe(
        false,
      )
    })

    it('lte includes equal', () => {
      expect(evalConditionGroup(req, { all: [{ field: 'subject.attributes.level', operator: 'lte', value: 5 }] })).toBe(
        true,
      )
    })

    it('numeric ops return false for non-number fields', () => {
      expect(evalConditionGroup(req, { all: [{ field: 'action', operator: 'gt', value: 3 }] })).toBe(false)
    })
  })

  describe('in / nin', () => {
    it('in checks if value is in array', () => {
      expect(evalConditionGroup(req, { all: [{ field: 'action', operator: 'in', value: ['read', 'write'] }] })).toBe(
        true,
      )
      expect(evalConditionGroup(req, { all: [{ field: 'action', operator: 'in', value: ['write', 'delete'] }] })).toBe(
        false,
      )
    })

    it('in with array field checks intersection', () => {
      expect(
        evalConditionGroup(req, {
          all: [{ field: 'resource.attributes.tags', operator: 'in', value: ['tech', 'sports'] }],
        }),
      ).toBe(true)
      expect(
        evalConditionGroup(req, {
          all: [{ field: 'resource.attributes.tags', operator: 'in', value: ['sports', 'music'] }],
        }),
      ).toBe(false)
    })

    it('nin is the negation of in', () => {
      expect(evalConditionGroup(req, { all: [{ field: 'action', operator: 'nin', value: ['write', 'delete'] }] })).toBe(
        true,
      )
      expect(evalConditionGroup(req, { all: [{ field: 'action', operator: 'nin', value: ['read', 'write'] }] })).toBe(
        false,
      )
    })
  })

  describe('contains / not_contains', () => {
    it('array contains scalar', () => {
      expect(
        evalConditionGroup(req, { all: [{ field: 'subject.roles', operator: 'contains', value: 'editor' }] }),
      ).toBe(true)
      expect(evalConditionGroup(req, { all: [{ field: 'subject.roles', operator: 'contains', value: 'admin' }] })).toBe(
        false,
      )
    })

    it('string contains substring', () => {
      expect(
        evalConditionGroup(req, {
          all: [{ field: 'subject.attributes.department', operator: 'contains', value: 'engine' }],
        }),
      ).toBe(true)
    })

    it('not_contains is the negation', () => {
      expect(
        evalConditionGroup(req, { all: [{ field: 'subject.roles', operator: 'not_contains', value: 'admin' }] }),
      ).toBe(true)
      expect(
        evalConditionGroup(req, { all: [{ field: 'subject.roles', operator: 'not_contains', value: 'editor' }] }),
      ).toBe(false)
    })
  })

  describe('starts_with / ends_with', () => {
    it('starts_with checks string prefix', () => {
      expect(
        evalConditionGroup(req, {
          all: [{ field: 'subject.attributes.department', operator: 'starts_with', value: 'eng' }],
        }),
      ).toBe(true)
      expect(
        evalConditionGroup(req, {
          all: [{ field: 'subject.attributes.department', operator: 'starts_with', value: 'mark' }],
        }),
      ).toBe(false)
    })

    it('ends_with checks string suffix', () => {
      expect(
        evalConditionGroup(req, {
          all: [{ field: 'subject.attributes.department', operator: 'ends_with', value: 'ing' }],
        }),
      ).toBe(true)
    })

    it('returns false for non-strings', () => {
      expect(
        evalConditionGroup(req, {
          all: [{ field: 'subject.attributes.level', operator: 'starts_with', value: '5' }],
        }),
      ).toBe(false)
    })
  })

  describe('matches', () => {
    it('tests regex patterns', () => {
      expect(
        evalConditionGroup(req, {
          all: [{ field: 'subject.attributes.department', operator: 'matches', value: '^eng.*ing$' }],
        }),
      ).toBe(true)
      expect(
        evalConditionGroup(req, {
          all: [{ field: 'subject.attributes.department', operator: 'matches', value: '^marketing$' }],
        }),
      ).toBe(false)
    })

    it('rejects invalid regex gracefully', () => {
      expect(
        evalConditionGroup(req, {
          all: [{ field: 'subject.attributes.department', operator: 'matches', value: '[invalid' }],
        }),
      ).toBe(false)
    })

    it('rejects overly long patterns (ReDoS protection)', () => {
      const longPattern = 'a'.repeat(600)
      expect(
        evalConditionGroup(req, {
          all: [{ field: 'subject.attributes.department', operator: 'matches', value: longPattern }],
        }),
      ).toBe(false)
    })
  })

  describe('exists / not_exists', () => {
    it('exists returns true for present fields', () => {
      expect(evalConditionGroup(req, { all: [{ field: 'subject.id', operator: 'exists' }] })).toBe(true)
    })

    it('exists returns false for null/undefined fields', () => {
      expect(evalConditionGroup(req, { all: [{ field: 'subject.attributes.missing', operator: 'exists' }] })).toBe(
        false,
      )
    })

    it('not_exists returns true for missing fields', () => {
      expect(evalConditionGroup(req, { all: [{ field: 'subject.attributes.missing', operator: 'not_exists' }] })).toBe(
        true,
      )
    })
  })

  describe('subset_of / superset_of', () => {
    it('subset_of checks if all field items are in value array', () => {
      expect(
        evalConditionGroup(req, {
          all: [{ field: 'resource.attributes.tags', operator: 'subset_of', value: ['tech', 'news', 'sports'] }],
        }),
      ).toBe(true)
      expect(
        evalConditionGroup(req, {
          all: [{ field: 'resource.attributes.tags', operator: 'subset_of', value: ['tech'] }],
        }),
      ).toBe(false)
    })

    it('superset_of checks if field array contains all value items', () => {
      expect(
        evalConditionGroup(req, {
          all: [{ field: 'resource.attributes.tags', operator: 'superset_of', value: ['tech'] }],
        }),
      ).toBe(true)
      expect(
        evalConditionGroup(req, {
          all: [{ field: 'resource.attributes.tags', operator: 'superset_of', value: ['tech', 'sports'] }],
        }),
      ).toBe(false)
    })
  })
})

describe('condition groups', () => {
  const req = makeReq()

  it('all: requires every condition to pass', () => {
    const group: AccessControl.IConditionGroup = {
      all: [
        { field: 'action', operator: 'eq', value: 'read' },
        { field: 'subject.id', operator: 'eq', value: 'user-1' },
      ],
    }
    expect(evalConditionGroup(req, group)).toBe(true)
  })

  it('all: fails if any condition fails', () => {
    const group: AccessControl.IConditionGroup = {
      all: [
        { field: 'action', operator: 'eq', value: 'read' },
        { field: 'subject.id', operator: 'eq', value: 'user-999' },
      ],
    }
    expect(evalConditionGroup(req, group)).toBe(false)
  })

  it('any: passes if at least one condition passes', () => {
    const group: AccessControl.IConditionGroup = {
      any: [
        { field: 'action', operator: 'eq', value: 'write' },
        { field: 'action', operator: 'eq', value: 'read' },
      ],
    }
    expect(evalConditionGroup(req, group)).toBe(true)
  })

  it('any: fails if all conditions fail', () => {
    const group: AccessControl.IConditionGroup = {
      any: [
        { field: 'action', operator: 'eq', value: 'write' },
        { field: 'action', operator: 'eq', value: 'delete' },
      ],
    }
    expect(evalConditionGroup(req, group)).toBe(false)
  })

  it('none: passes if no conditions pass', () => {
    const group: AccessControl.IConditionGroup = {
      none: [
        { field: 'action', operator: 'eq', value: 'write' },
        { field: 'action', operator: 'eq', value: 'delete' },
      ],
    }
    expect(evalConditionGroup(req, group)).toBe(true)
  })

  it('none: fails if any condition passes', () => {
    const group: AccessControl.IConditionGroup = {
      none: [
        { field: 'action', operator: 'eq', value: 'read' },
        { field: 'action', operator: 'eq', value: 'delete' },
      ],
    }
    expect(evalConditionGroup(req, group)).toBe(false)
  })

  it('nested groups work', () => {
    const group: AccessControl.IConditionGroup = {
      all: [
        { field: 'action', operator: 'eq', value: 'read' },
        {
          any: [
            { field: 'subject.id', operator: 'eq', value: 'user-999' },
            { field: 'subject.roles', operator: 'contains', value: 'editor' },
          ],
        },
      ],
    }
    expect(evalConditionGroup(req, group)).toBe(true)
  })
})

describe('$-variable resolution in condition values', () => {
  it('resolves $subject.id to the actual subject id', () => {
    const req = makeReq()
    // isOwner check: resource.attributes.ownerId eq $subject.id
    const group: AccessControl.IConditionGroup = {
      all: [{ field: 'resource.attributes.ownerId', operator: 'eq', value: '$subject.id' }],
    }
    expect(evalConditionGroup(req, group)).toBe(true)
  })

  it('fails when $subject.id does not match', () => {
    const req = makeReq({
      resource: {
        type: 'post',
        id: 'post-42',
        attributes: { ownerId: 'user-other', published: true },
      },
    })
    const group: AccessControl.IConditionGroup = {
      all: [{ field: 'resource.attributes.ownerId', operator: 'eq', value: '$subject.id' }],
    }
    expect(evalConditionGroup(req, group)).toBe(false)
  })

  it('resolves $ references for other paths', () => {
    const req = makeReq()
    // Check if resource.attributes.ownerId is in subject.roles (nonsensical but tests resolution)
    const group: AccessControl.IConditionGroup = {
      all: [{ field: 'subject.id', operator: 'eq', value: '$resource.attributes.ownerId' }],
    }
    expect(evalConditionGroup(req, group)).toBe(true)
  })

  it('non-$ values are used literally', () => {
    const req = makeReq()
    const group: AccessControl.IConditionGroup = {
      all: [{ field: 'action', operator: 'eq', value: 'read' }],
    }
    expect(evalConditionGroup(req, group)).toBe(true)
  })
})

describe('matches operator safety (C2)', () => {
  it('refuses $-resolved patterns regardless of attribute content', () => {
    // Even a benign-looking attribute is refused: the regex source must be
    // literal in the policy, not pulled from request data.
    const req = makeReq({
      subject: { id: 'u', roles: [], attributes: { pattern: '^hello$' } },
    })
    const group: AccessControl.IConditionGroup = {
      all: [{ field: 'subject.id', operator: 'matches', value: '$subject.attributes.pattern' }],
    }
    expect(evalConditionGroup(req, group)).toBe(false)
  })

  it('accepts literal patterns', () => {
    const req = makeReq({ subject: { id: 'hello', roles: [], attributes: {} } })
    const group: AccessControl.IConditionGroup = {
      all: [{ field: 'subject.id', operator: 'matches', value: '^hello$' }],
    }
    expect(evalConditionGroup(req, group)).toBe(true)
  })

  it('blocks catastrophic regex even if the attribute looks safe', () => {
    // A user-controlled attribute can never reach the regex engine: we refuse
    // the $-resolved value upfront, so the well-known
    // `(a+)+$` ReDoS pattern never even gets compiled.
    const req = makeReq({
      subject: { id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!', roles: [], attributes: { p: '^(a+)+$' } },
    })
    const start = performance.now()
    const group: AccessControl.IConditionGroup = {
      all: [{ field: 'subject.id', operator: 'matches', value: '$subject.attributes.p' }],
    }
    expect(evalConditionGroup(req, group)).toBe(false)
    expect(performance.now() - start).toBeLessThan(50)
  })
})

describe('regex cache LRU (M1)', () => {
  it('a hot pattern survives REGEX_CACHE_MAX cold compiles after it', async () => {
    const { getCachedRegex, regexCache, REGEX_CACHE_MAX } = await import('../conditions.libs')
    regexCache.clear()
    const hot = 'hot-pattern-[a-z]+'
    getCachedRegex(hot)
    for (let i = 0; i < REGEX_CACHE_MAX; i++) getCachedRegex(`cold-${i}`)
    // Touch hot in between so it stays warm
    getCachedRegex(hot)
    for (let i = REGEX_CACHE_MAX; i < REGEX_CACHE_MAX * 2 - 1; i++) getCachedRegex(`cold-${i}`)
    expect(regexCache.has(hot)).toBe(true)
    regexCache.clear()
  })
})

describe('matches operator ReDoS hardening (P1)', () => {
  it('evaluates a catastrophic pattern + adversarial-length input under 50ms', async () => {
    const { regexCache, RegexInputTooLargeError } = await import('../conditions.libs')
    regexCache.clear()
    const big = `${'a'.repeat(3000)}!`
    const req = makeReq({ subject: { id: big, roles: [], attributes: {} } })
    const group: AccessControl.IConditionGroup = {
      all: [{ field: 'subject.id', operator: 'matches', value: '(a+)+$' }],
    }
    const start = performance.now()
    let caught: unknown
    try {
      evalConditionGroup(req, group)
    } catch (e) {
      caught = e
    }
    const elapsed = performance.now() - start
    expect(caught).toBeInstanceOf(RegexInputTooLargeError)
    expect(elapsed).toBeLessThan(50)
  })

  it('throws RegexInputTooLargeError on inputs longer than MAX_REGEX_INPUT_LENGTH instead of returning false', async () => {
    const { MAX_REGEX_INPUT_LENGTH, RegexInputTooLargeError, regexCache } = await import('../conditions.libs')
    regexCache.clear()
    // A silent `false` would flip `deny`-when-`matches` rules into
    // "condition not met -> allow". The operator throws a tagged error so
    // safeEval can route it through onPolicyError and drop the whole policy
    // as NotApplicable instead.
    const big = 'a'.repeat(10_000)
    expect(big.length).toBeGreaterThan(MAX_REGEX_INPUT_LENGTH)
    const req = makeReq({ subject: { id: big, roles: [], attributes: {} } })
    const pattern = '^a+$'
    const group: AccessControl.IConditionGroup = {
      all: [{ field: 'subject.id', operator: 'matches', value: pattern }],
    }
    let caught: unknown
    try {
      evalConditionGroup(req, group)
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(RegexInputTooLargeError)
    expect((caught as InstanceType<typeof RegexInputTooLargeError>).field).toBe('subject.id')
    expect((caught as InstanceType<typeof RegexInputTooLargeError>).length).toBe(10_000)
    expect((caught as InstanceType<typeof RegexInputTooLargeError>).tag).toBe('duck-iam/regex-input-too-large')
    // The operator throws before compiling the regex.
    expect(regexCache.has(pattern)).toBe(false)
  })

  it('deny-when-matches over-length input drops policy (decision = deny, not allow)', async () => {
    const { evaluate } = await import('../../evaluate')
    const policy: AccessControl.IPolicy = {
      id: 'deny-evil',
      name: 'Deny evil subjects',
      algorithm: 'deny-overrides',
      rules: [
        {
          id: 'r1',
          effect: 'deny',
          priority: 100,
          actions: ['read'],
          resources: ['post'],
          conditions: { all: [{ field: 'subject.id', operator: 'matches', value: '^evil-' }] },
        },
      ],
    }
    const bigId = 'a'.repeat(10_000)
    const req: IamRequest.IAccessRequest = {
      subject: { id: bigId, roles: [], attributes: {} },
      action: 'read',
      resource: { type: 'post', id: 'post-1', attributes: {} },
    }
    const errors: Array<{ msg: string; policyId: string }> = []
    const decision = evaluate([policy], req, 'deny', 'and', (err, p) =>
      errors.push({ msg: err.message, policyId: p.id }),
    )
    // Critical: NOT `allowed: true`. Final decision must be deny.
    expect(decision.allowed).toBe(false)
    expect(decision.effect).toBe('deny')
    // The drop happens via policy-error path, not via the matches rule firing
    // as `deny`. Reason text reflects the no-applicable-policy fall-through.
    expect(decision.reason).toMatch(/No policy applicable|Policy evaluation error/i)
    // onPolicyError was invoked with the tagged error.
    expect(errors).toHaveLength(1)
    expect(errors[0]?.policyId).toBe('deny-evil')
    expect(errors[0]?.msg).toMatch(/MAX_REGEX_INPUT_LENGTH|matches input/)
  })

  it('exposes MAX_REGEX_LENGTH tightened to 128', async () => {
    const { MAX_REGEX_LENGTH } = await import('../conditions.libs')
    expect(MAX_REGEX_LENGTH).toBe(128)
  })
})

describe('nesting depth fail-closed (MAX_CONDITION_DEPTH)', () => {
  const truthy: AccessControl.ICondition = { field: 'subject.id', operator: 'eq', value: 'user-1' }

  /** `{ all: [{ all: [ ... leaf ] }] }` nested `levels` groups deep. */
  function nest(levels: number, leaf: AccessControl.ICondition): AccessControl.IConditionGroup {
    let group: AccessControl.IConditionGroup = { all: [leaf] }
    for (let i = 1; i < levels; i++) group = { all: [group] }
    return group
  }

  it('evaluates a tree sitting exactly on the depth bound', async () => {
    const { MAX_CONDITION_DEPTH } = await import('../conditions.libs')
    expect(evalConditionGroup(makeReq(), nest(MAX_CONDITION_DEPTH, truthy))).toBe(true)
  })

  it('denies a tree deeper than the bound even though every leaf is true', async () => {
    const { MAX_CONDITION_DEPTH } = await import('../conditions.libs')
    expect(evalConditionGroup(makeReq(), nest(MAX_CONDITION_DEPTH + 1, truthy))).toBe(false)
  })

  it('an over-deep `none` group also fails closed rather than negating to true', async () => {
    const { MAX_CONDITION_DEPTH } = await import('../conditions.libs')
    let group: AccessControl.IConditionGroup = { none: [truthy] }
    for (let i = 1; i < MAX_CONDITION_DEPTH + 1; i++) group = { none: [group] }
    expect(evalConditionGroup(makeReq(), group)).toBe(false)
  })
})

describe('condition helpers', () => {
  it('evaluateOperator applies the named operator directly', async () => {
    const { evaluateOperator } = await import('../conditions')
    expect(evaluateOperator('eq', 'a', 'a')).toBe(true)
    expect(evaluateOperator('gt', 5, 3)).toBe(true)
    expect(evaluateOperator('gt', 3, 5)).toBe(false)
    expect(evaluateOperator('not_exists', null, null)).toBe(true)
  })

  it('resolveConditionValue resolves $-references and passes literals through', async () => {
    const { resolveConditionValue } = await import('../conditions')
    const req = makeReq()
    expect(resolveConditionValue(req, '$subject.id')).toBe('user-1')
    expect(resolveConditionValue(req, '$resource.attributes.ownerId')).toBe('user-1')
    expect(resolveConditionValue(req, 'user-1')).toBe('user-1')
    expect(resolveConditionValue(req, 42)).toBe(42)
    // Unknown root resolves to null, not to the literal string.
    expect(resolveConditionValue(req, '$nope.nope')).toBeNull()
  })

  it('isCondition separates leaf conditions from groups', async () => {
    const { isCondition } = await import('../conditions.libs')
    expect(isCondition({ field: 'subject.id', operator: 'eq', value: 'x' })).toBe(true)
    expect(isCondition({ all: [] })).toBe(false)
    expect(isCondition({ any: [] })).toBe(false)
    expect(isCondition({ none: [] })).toBe(false)
  })

  it('isUserSourcedValue flags only $-prefixed strings', async () => {
    const { isUserSourcedValue } = await import('../conditions.libs')
    expect(isUserSourcedValue('$subject.id')).toBe(true)
    expect(isUserSourcedValue('subject.id')).toBe(false)
    expect(isUserSourcedValue('')).toBe(false)
    expect(isUserSourcedValue(null)).toBe(false)
    expect(isUserSourcedValue(42)).toBe(false)
  })
})

describe('per-instance regex cache isolation', () => {
  it('evalMatchesOp compiles into the supplied cache and leaves the global one untouched', async () => {
    const { evalMatchesOp, regexCache } = await import('../conditions.libs')
    const pattern = `^tenant-${Math.random().toString(36).slice(2)}-`
    const tenantCache = new Map<string, RegExp>()
    expect(evalMatchesOp('abc', pattern, tenantCache)).toBe(false)
    expect(tenantCache.has(pattern)).toBe(true)
    expect(regexCache.has(pattern)).toBe(false)
  })

  it('evalMatchesOp rejects over-long patterns and non-string operands without compiling', async () => {
    const { evalMatchesOp, MAX_REGEX_LENGTH } = await import('../conditions.libs')
    const cache = new Map<string, RegExp>()
    const longPattern = `^${'a'.repeat(MAX_REGEX_LENGTH)}`
    expect(evalMatchesOp('aaa', longPattern, cache)).toBe(false)
    expect(cache.size).toBe(0)
    expect(evalMatchesOp(42, '^4', cache)).toBe(false)
    expect(evalMatchesOp('42', 42, cache)).toBe(false)
    expect(cache.size).toBe(0)
  })

  it('evalMatchesOp throws on over-length input instead of returning false', async () => {
    const { evalMatchesOp, MAX_REGEX_INPUT_LENGTH, RegexInputTooLargeError } = await import('../conditions.libs')
    const cache = new Map<string, RegExp>()
    expect(() => evalMatchesOp('a'.repeat(MAX_REGEX_INPUT_LENGTH + 1), '^a', cache)).toThrow(RegexInputTooLargeError)
  })

  it('clearRegexCache empties the process-wide cache only', async () => {
    const { clearRegexCache, evalMatchesOp, getCachedRegex, regexCache } = await import('../conditions.libs')
    const tenantCache = new Map<string, RegExp>()
    getCachedRegex('^global-')
    evalMatchesOp('tenant-1', '^tenant-', tenantCache)
    expect(regexCache.size).toBeGreaterThan(0)
    clearRegexCache()
    expect(regexCache.size).toBe(0)
    expect(tenantCache.has('^tenant-')).toBe(true)
  })
})
