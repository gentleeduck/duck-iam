import { describe, expect, it } from 'vitest'
import { buildScopeTrie, resolveScopeMask } from '../compiled.scope'

describe('buildScopeTrie / resolveScopeMask', () => {
  it('unions masks for grants at the same scope', () => {
    const trie = buildScopeTrie([
      { scope: 'org-1', allow: 0b01, deny: 0 },
      { scope: 'org-1', allow: 0b10, deny: 0 },
    ])
    expect(trie.get('org-1')).toEqual({ allow: 0b11, deny: 0 })
  })

  it('union combine: sums grants across every matching ancestor level', () => {
    const trie = buildScopeTrie([
      { scope: 'org-1', allow: 0b001, deny: 0 },
      { scope: 'org-1.team-2', allow: 0b010, deny: 0 },
    ])
    expect(resolveScopeMask(trie, 'org-1.team-2.repo-3', 'union')).toEqual({ allow: 0b011, deny: 0 })
  })

  it('override combine: stops at the first (most specific) matching level', () => {
    const trie = buildScopeTrie([
      { scope: 'org-1', allow: 0b001, deny: 0 },
      { scope: 'org-1.team-2.repo-3', allow: 0b100, deny: 0 },
    ])
    expect(resolveScopeMask(trie, 'org-1.team-2.repo-3', 'override')).toEqual({ allow: 0b100, deny: 0 })
  })

  it('override combine: falls through to a broader level when no narrower grant exists', () => {
    const trie = buildScopeTrie([{ scope: 'org-1', allow: 0b001, deny: 0 }])
    expect(resolveScopeMask(trie, 'org-1.team-2.repo-3', 'override')).toEqual({ allow: 0b001, deny: 0 })
  })

  it('no matching level: zero mask', () => {
    const trie = buildScopeTrie([{ scope: 'org-2', allow: 0b001, deny: 0 }])
    expect(resolveScopeMask(trie, 'org-1.team-2', 'union')).toEqual({ allow: 0, deny: 0 })
  })
})
