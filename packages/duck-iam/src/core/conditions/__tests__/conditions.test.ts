import { describe, expect, it } from 'vitest'
import type { IamAccessControl, IamRequest } from '../../types'
import { iamEvalConditionGroup } from '../conditions'

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
      expect(iamEvalConditionGroup(req, { all: [{ field: 'action', operator: 'eq', value: 'read' }] })).toBe(true)
    })

    it('eq rejects unequal values', () => {
      expect(iamEvalConditionGroup(req, { all: [{ field: 'action', operator: 'eq', value: 'write' }] })).toBe(false)
    })

    it('neq matches unequal values', () => {
      expect(iamEvalConditionGroup(req, { all: [{ field: 'action', operator: 'neq', value: 'write' }] })).toBe(true)
    })
  })

  describe('gt / gte / lt / lte', () => {
    it('gt compares numbers', () => {
      expect(iamEvalConditionGroup(req, { all: [{ field: 'subject.attributes.level', operator: 'gt', value: 3 }] })).toBe(
        true,
      )
      expect(iamEvalConditionGroup(req, { all: [{ field: 'subject.attributes.level', operator: 'gt', value: 5 }] })).toBe(
        false,
      )
    })

    it('gte includes equal', () => {
      expect(iamEvalConditionGroup(req, { all: [{ field: 'subject.attributes.level', operator: 'gte', value: 5 }] })).toBe(
        true,
      )
    })

    it('lt compares numbers', () => {
      expect(iamEvalConditionGroup(req, { all: [{ field: 'subject.attributes.level', operator: 'lt', value: 10 }] })).toBe(
        true,
      )
      expect(iamEvalConditionGroup(req, { all: [{ field: 'subject.attributes.level', operator: 'lt', value: 5 }] })).toBe(
        false,
      )
    })

    it('lte includes equal', () => {
      expect(iamEvalConditionGroup(req, { all: [{ field: 'subject.attributes.level', operator: 'lte', value: 5 }] })).toBe(
        true,
      )
    })

    it('numeric iamOps return false for non-number fields', () => {
      expect(iamEvalConditionGroup(req, { all: [{ field: 'action', operator: 'gt', value: 3 }] })).toBe(false)
    })
  })

  describe('in / nin', () => {
    it('in checks if value is in array', () => {
      expect(iamEvalConditionGroup(req, { all: [{ field: 'action', operator: 'in', value: ['read', 'write'] }] })).toBe(
        true,
      )
      expect(iamEvalConditionGroup(req, { all: [{ field: 'action', operator: 'in', value: ['write', 'delete'] }] })).toBe(
        false,
      )
    })

    it('in with array field checks intersection', () => {
      expect(
        iamEvalConditionGroup(req, {
          all: [{ field: 'resource.attributes.tags', operator: 'in', value: ['tech', 'sports'] }],
        }),
      ).toBe(true)
      expect(
        iamEvalConditionGroup(req, {
          all: [{ field: 'resource.attributes.tags', operator: 'in', value: ['sports', 'music'] }],
        }),
      ).toBe(false)
    })

    it('nin is the negation of in', () => {
      expect(iamEvalConditionGroup(req, { all: [{ field: 'action', operator: 'nin', value: ['write', 'delete'] }] })).toBe(
        true,
      )
      expect(iamEvalConditionGroup(req, { all: [{ field: 'action', operator: 'nin', value: ['read', 'write'] }] })).toBe(
        false,
      )
    })
  })

  describe('contains / not_contains', () => {
    it('array contains scalar', () => {
      expect(
        iamEvalConditionGroup(req, { all: [{ field: 'subject.roles', operator: 'contains', value: 'editor' }] }),
      ).toBe(true)
      expect(iamEvalConditionGroup(req, { all: [{ field: 'subject.roles', operator: 'contains', value: 'admin' }] })).toBe(
        false,
      )
    })

    it('string contains substring', () => {
      expect(
        iamEvalConditionGroup(req, {
          all: [{ field: 'subject.attributes.department', operator: 'contains', value: 'engine' }],
        }),
      ).toBe(true)
    })

    it('not_contains is the negation', () => {
      expect(
        iamEvalConditionGroup(req, { all: [{ field: 'subject.roles', operator: 'not_contains', value: 'admin' }] }),
      ).toBe(true)
      expect(
        iamEvalConditionGroup(req, { all: [{ field: 'subject.roles', operator: 'not_contains', value: 'editor' }] }),
      ).toBe(false)
    })
  })

  describe('starts_with / ends_with', () => {
    it('starts_with checks string prefix', () => {
      expect(
        iamEvalConditionGroup(req, {
          all: [{ field: 'subject.attributes.department', operator: 'starts_with', value: 'eng' }],
        }),
      ).toBe(true)
      expect(
        iamEvalConditionGroup(req, {
          all: [{ field: 'subject.attributes.department', operator: 'starts_with', value: 'mark' }],
        }),
      ).toBe(false)
    })

    it('ends_with checks string suffix', () => {
      expect(
        iamEvalConditionGroup(req, {
          all: [{ field: 'subject.attributes.department', operator: 'ends_with', value: 'ing' }],
        }),
      ).toBe(true)
    })

    it('returns false for non-strings', () => {
      expect(
        iamEvalConditionGroup(req, { all: [{ field: 'subject.attributes.level', operator: 'starts_with', value: '5' }] }),
      ).toBe(false)
    })
  })

  describe('matches', () => {
    it('tests regex patterns', () => {
      expect(
        iamEvalConditionGroup(req, {
          all: [{ field: 'subject.attributes.department', operator: 'matches', value: '^eng.*ing$' }],
        }),
      ).toBe(true)
      expect(
        iamEvalConditionGroup(req, {
          all: [{ field: 'subject.attributes.department', operator: 'matches', value: '^marketing$' }],
        }),
      ).toBe(false)
    })

    it('rejects invalid regex gracefully', () => {
      expect(
        iamEvalConditionGroup(req, {
          all: [{ field: 'subject.attributes.department', operator: 'matches', value: '[invalid' }],
        }),
      ).toBe(false)
    })

    it('rejects overly long patterns (ReDoS protection)', () => {
      const longPattern = 'a'.repeat(600)
      expect(
        iamEvalConditionGroup(req, {
          all: [{ field: 'subject.attributes.department', operator: 'matches', value: longPattern }],
        }),
      ).toBe(false)
    })
  })

  describe('exists / not_exists', () => {
    it('exists returns true for present fields', () => {
      expect(iamEvalConditionGroup(req, { all: [{ field: 'subject.id', operator: 'exists' }] })).toBe(true)
    })

    it('exists returns false for null/undefined fields', () => {
      expect(iamEvalConditionGroup(req, { all: [{ field: 'subject.attributes.missing', operator: 'exists' }] })).toBe(
        false,
      )
    })

    it('not_exists returns true for missing fields', () => {
      expect(iamEvalConditionGroup(req, { all: [{ field: 'subject.attributes.missing', operator: 'not_exists' }] })).toBe(
        true,
      )
    })
  })

  describe('subset_of / superset_of', () => {
    it('subset_of checks if all field items are in value array', () => {
      expect(
        iamEvalConditionGroup(req, {
          all: [{ field: 'resource.attributes.tags', operator: 'subset_of', value: ['tech', 'news', 'sports'] }],
        }),
      ).toBe(true)
      expect(
        iamEvalConditionGroup(req, {
          all: [{ field: 'resource.attributes.tags', operator: 'subset_of', value: ['tech'] }],
        }),
      ).toBe(false)
    })

    it('superset_of checks if field array contains all value items', () => {
      expect(
        iamEvalConditionGroup(req, {
          all: [{ field: 'resource.attributes.tags', operator: 'superset_of', value: ['tech'] }],
        }),
      ).toBe(true)
      expect(
        iamEvalConditionGroup(req, {
          all: [{ field: 'resource.attributes.tags', operator: 'superset_of', value: ['tech', 'sports'] }],
        }),
      ).toBe(false)
    })
  })
})

describe('condition groups', () => {
  const req = makeReq()

  it('all: requires every condition to pass', () => {
    const group: IamAccessControl.IConditionGroup = {
      all: [
        { field: 'action', operator: 'eq', value: 'read' },
        { field: 'subject.id', operator: 'eq', value: 'user-1' },
      ],
    }
    expect(iamEvalConditionGroup(req, group)).toBe(true)
  })

  it('all: fails if any condition fails', () => {
    const group: IamAccessControl.IConditionGroup = {
      all: [
        { field: 'action', operator: 'eq', value: 'read' },
        { field: 'subject.id', operator: 'eq', value: 'user-999' },
      ],
    }
    expect(iamEvalConditionGroup(req, group)).toBe(false)
  })

  it('any: passes if at least one condition passes', () => {
    const group: IamAccessControl.IConditionGroup = {
      any: [
        { field: 'action', operator: 'eq', value: 'write' },
        { field: 'action', operator: 'eq', value: 'read' },
      ],
    }
    expect(iamEvalConditionGroup(req, group)).toBe(true)
  })

  it('any: fails if all conditions fail', () => {
    const group: IamAccessControl.IConditionGroup = {
      any: [
        { field: 'action', operator: 'eq', value: 'write' },
        { field: 'action', operator: 'eq', value: 'delete' },
      ],
    }
    expect(iamEvalConditionGroup(req, group)).toBe(false)
  })

  it('none: passes if no conditions pass', () => {
    const group: IamAccessControl.IConditionGroup = {
      none: [
        { field: 'action', operator: 'eq', value: 'write' },
        { field: 'action', operator: 'eq', value: 'delete' },
      ],
    }
    expect(iamEvalConditionGroup(req, group)).toBe(true)
  })

  it('none: fails if any condition passes', () => {
    const group: IamAccessControl.IConditionGroup = {
      none: [
        { field: 'action', operator: 'eq', value: 'read' },
        { field: 'action', operator: 'eq', value: 'delete' },
      ],
    }
    expect(iamEvalConditionGroup(req, group)).toBe(false)
  })

  it('nested groups work', () => {
    const group: IamAccessControl.IConditionGroup = {
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
    expect(iamEvalConditionGroup(req, group)).toBe(true)
  })
})

describe('$-variable resolution in condition values', () => {
  it('resolves $subject.id to the actual subject id', () => {
    const req = makeReq()
    // isOwner check: resource.attributes.ownerId eq $subject.id
    const group: IamAccessControl.IConditionGroup = {
      all: [{ field: 'resource.attributes.ownerId', operator: 'eq', value: '$subject.id' }],
    }
    expect(iamEvalConditionGroup(req, group)).toBe(true)
  })

  it('fails when $subject.id does not match', () => {
    const req = makeReq({
      resource: {
        type: 'post',
        id: 'post-42',
        attributes: { ownerId: 'user-other', published: true },
      },
    })
    const group: IamAccessControl.IConditionGroup = {
      all: [{ field: 'resource.attributes.ownerId', operator: 'eq', value: '$subject.id' }],
    }
    expect(iamEvalConditionGroup(req, group)).toBe(false)
  })

  it('resolves $ references for other paths', () => {
    const req = makeReq()
    // Check if resource.attributes.ownerId is in subject.roles (nonsensical but tests resolution)
    const group: IamAccessControl.IConditionGroup = {
      all: [{ field: 'subject.id', operator: 'eq', value: '$resource.attributes.ownerId' }],
    }
    expect(iamEvalConditionGroup(req, group)).toBe(true)
  })

  it('non-$ values are used literally', () => {
    const req = makeReq()
    const group: IamAccessControl.IConditionGroup = {
      all: [{ field: 'action', operator: 'eq', value: 'read' }],
    }
    expect(iamEvalConditionGroup(req, group)).toBe(true)
  })
})

describe('matches operator safety (C2)', () => {
  it('refuses $-resolved patterns regardless of attribute content', () => {
    // Even a benign-looking attribute is refused: the regex source must be
    // literal in the policy, not pulled from request data.
    const req = makeReq({
      subject: { id: 'u', roles: [], attributes: { pattern: '^hello$' } },
    })
    const group: IamAccessControl.IConditionGroup = {
      all: [{ field: 'subject.id', operator: 'matches', value: '$subject.attributes.pattern' }],
    }
    expect(iamEvalConditionGroup(req, group)).toBe(false)
  })

  it('accepts literal patterns', () => {
    const req = makeReq({ subject: { id: 'hello', roles: [], attributes: {} } })
    const group: IamAccessControl.IConditionGroup = {
      all: [{ field: 'subject.id', operator: 'matches', value: '^hello$' }],
    }
    expect(iamEvalConditionGroup(req, group)).toBe(true)
  })

  it('blocks catastrophic regex even if the attribute looks safe', () => {
    // A user-controlled attribute can never reach the regex engine: we refuse
    // the $-resolved value upfront, so the well-known
    // `(a+)+$` ReDoS pattern never even gets compiled.
    const req = makeReq({
      subject: { id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!', roles: [], attributes: { p: '^(a+)+$' } },
    })
    const start = performance.now()
    const group: IamAccessControl.IConditionGroup = {
      all: [{ field: 'subject.id', operator: 'matches', value: '$subject.attributes.p' }],
    }
    expect(iamEvalConditionGroup(req, group)).toBe(false)
    expect(performance.now() - start).toBeLessThan(50)
  })
})

describe('regex cache LRU (M1)', () => {
  it('a hot pattern survives IAM_REGEX_CACHE_MAX cold compiles after it', async () => {
    const { iamGetCachedRegex, iamRegexCache, IAM_REGEX_CACHE_MAX } = await import('../conditions.libs')
    iamRegexCache.clear()
    const hot = 'hot-pattern-[a-z]+'
    iamGetCachedRegex(hot)
    for (let i = 0; i < IAM_REGEX_CACHE_MAX; i++) iamGetCachedRegex(`cold-${i}`)
    // Touch hot in between so it stays warm
    iamGetCachedRegex(hot)
    for (let i = IAM_REGEX_CACHE_MAX; i < IAM_REGEX_CACHE_MAX * 2 - 1; i++) iamGetCachedRegex(`cold-${i}`)
    expect(iamRegexCache.has(hot)).toBe(true)
    iamRegexCache.clear()
  })
})

describe('matches operator ReDoS hardening (P1)', () => {
  it('evaluates a catastrophic pattern + adversarial-length input under 50ms', async () => {
    const { iamRegexCache, IamRegexInputTooLargeError } = await import('../conditions.libs')
    iamRegexCache.clear()
    const big = `${'a'.repeat(3000)}!`
    const req = makeReq({ subject: { id: big, roles: [], attributes: {} } })
    const group: IamAccessControl.IConditionGroup = {
      all: [{ field: 'subject.id', operator: 'matches', value: '(a+)+$' }],
    }
    const start = performance.now()
    let caught: unknown
    try {
      iamEvalConditionGroup(req, group)
    } catch (e) {
      caught = e
    }
    const elapsed = performance.now() - start
    expect(caught).toBeInstanceOf(IamRegexInputTooLargeError)
    expect(elapsed).toBeLessThan(50)
  })

  it('throws IamRegexInputTooLargeError on inputs longer than IAM_MAX_REGEX_INPUT_LENGTH instead of returning false', async () => {
    const { IAM_MAX_REGEX_INPUT_LENGTH, IamRegexInputTooLargeError, iamRegexCache } = await import('../conditions.libs')
    iamRegexCache.clear()
    // A silent `false` would flip `deny`-when-`matches` rules into
    // "condition not met -> allow". The operator throws a tagged error so
    // safeEval can route it through onPolicyError and drop the whole policy
    // as NotApplicable instead.
    const big = 'a'.repeat(10_000)
    expect(big.length).toBeGreaterThan(IAM_MAX_REGEX_INPUT_LENGTH)
    const req = makeReq({ subject: { id: big, roles: [], attributes: {} } })
    const pattern = '^a+$'
    const group: IamAccessControl.IConditionGroup = {
      all: [{ field: 'subject.id', operator: 'matches', value: pattern }],
    }
    let caught: unknown
    try {
      iamEvalConditionGroup(req, group)
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(IamRegexInputTooLargeError)
    expect((caught as InstanceType<typeof IamRegexInputTooLargeError>).field).toBe('subject.id')
    expect((caught as InstanceType<typeof IamRegexInputTooLargeError>).length).toBe(10_000)
    expect((caught as InstanceType<typeof IamRegexInputTooLargeError>).tag).toBe('duck-iam/regex-input-too-large')
    // The operator throws before compiling the regex.
    expect(iamRegexCache.has(pattern)).toBe(false)
  })

  it('deny-when-matches over-length input drops policy (decision = deny, not allow)', async () => {
    const { iamEvaluate } = await import('../../evaluate')
    const policy: IamAccessControl.IPolicy = {
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
    const decision = iamEvaluate([policy], req, 'deny', 'and', (err, p) =>
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
    expect(errors[0]?.msg).toMatch(/IAM_MAX_REGEX_INPUT_LENGTH|matches input/)
  })

  it('exposes IAM_MAX_REGEX_LENGTH tightened to 128', async () => {
    const { IAM_MAX_REGEX_LENGTH } = await import('../conditions.libs')
    expect(IAM_MAX_REGEX_LENGTH).toBe(128)
  })
})
