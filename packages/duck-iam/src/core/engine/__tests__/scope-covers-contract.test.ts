import { describe, expect, it } from 'vitest'
import { matchesScope } from '../../resolve/resolve'
import { scopeCovers } from '../engine.libs'

/**
 * `matchesScope` documented the scope contract, was contract-tested, and was
 * called by nothing: scope matching happened in `rbac.ts`'s emitted condition
 * and in the compiled table's own comparison, neither of which shared a line
 * with it. Three expressions, one contract, and the truth tables had already
 * drifted apart. `scopeCovers` - the one imperative scope check left in the
 * engine - now routes its exact-match arm through `matchesScope`, so this
 * pins that they cannot drift again.
 */
const DECLARED = ['org-1', 'org-10', 'org-1.team-a', '*', ''] as const
const REQUESTED = [undefined, 'org-1', 'org-10', 'org-1.team-a', 'org-1.team-a.sub', '', 'org'] as const

describe('scopeCovers agrees with matchesScope on the flat axis', () => {
  for (const declared of DECLARED) {
    for (const requested of REQUESTED) {
      it(`declared ${JSON.stringify(declared)} vs request ${JSON.stringify(requested)}`, () => {
        expect(scopeCovers(declared, requested, 'flat')).toBe(matchesScope(declared, requested))
      })
    }
  }
})

describe('hierarchical adds descendants and nothing else', () => {
  it('covers a descendant', () => {
    expect(scopeCovers('org-1', 'org-1.team-a', 'hierarchical')).toBe(true)
    expect(scopeCovers('org-1', 'org-1.team-a', 'flat')).toBe(false)
  })

  it('does not cover a sibling that merely shares a prefix', () => {
    expect(scopeCovers('org-1', 'org-10', 'hierarchical')).toBe(false)
  })

  it('does not walk upward', () => {
    expect(scopeCovers('org-1.team-a', 'org-1', 'hierarchical')).toBe(false)
  })

  it('never grants on an absent request scope', () => {
    expect(scopeCovers('org-1', undefined, 'hierarchical')).toBe(false)
  })

  // `'*'` reaching `scopeCovers` is global. The `===` it replaced said no,
  // which `matchesScope` had documented as yes for as long as it existed.
  it("treats '*' as global in both modes", () => {
    expect(scopeCovers('*', 'anything', 'flat')).toBe(true)
    expect(scopeCovers('*', 'anything', 'hierarchical')).toBe(true)
    expect(scopeCovers('*', undefined, 'flat')).toBe(true)
  })

  it("treats '' as an ordinary scope value, never a wildcard", () => {
    expect(scopeCovers('', 'org-1', 'flat')).toBe(false)
    expect(scopeCovers('', 'org-1', 'hierarchical')).toBe(false)
    expect(scopeCovers('', '', 'flat')).toBe(true)
  })
})
