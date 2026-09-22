import { describe, expect, it } from 'vitest'
import * as pkg from '../../../index'
import { matchesScope } from '../../resolve/resolve'
import { scopeAncestors, scopeCovers } from '../engine.libs'

// `scopeCovers` routes its exact-match arm through `matchesScope`; this pins that the two cannot drift apart.
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

  // `'*'` reaching `scopeCovers` is global, as `matchesScope` documents.
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

// Callers reuse the engine's own scope walk instead of a reimplementation, so these pin identity, not behaviour.
describe('the scope walk is reachable from the package root', () => {
  it('exports the engine own scopeAncestors, not a copy', () => {
    expect(pkg.iamScopeAncestors).toBe(scopeAncestors)
  })

  it('exports the engine own scopeCovers alongside it', () => {
    expect(pkg.iamScopeCovers).toBe(scopeCovers)
  })

  it('walks a dotted scope up to its ancestors, most specific first', () => {
    expect(pkg.iamScopeAncestors('org-1.team-a.repo-3')).toEqual(['org-1.team-a.repo-3', 'org-1.team-a', 'org-1'])
  })

  it('returns a single-element walk for a scope with no ancestors', () => {
    expect(pkg.iamScopeAncestors('org-1')).toEqual(['org-1'])
  })
})
