import { describe, expect, it } from 'vitest'
import type { AccessControl } from '../../../types'
import { compileTable } from '../compiled.compile'
import { lookupScoped } from '../compiled.lookup'
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

describe('lookupScoped: scope overlay gates ROLE_MASK and DYNAMIC cells alike', () => {
  it('scope-deny gates a ROLE_MASK cell the subject would otherwise pass', () => {
    const roles: AccessControl.IRole[] = [
      { id: 'editor', name: 'Editor', permissions: [{ action: 'update', resource: 'repo' }] },
    ]
    const t = compileTable(roles, [])
    const editorBit = 1 << t.roleId.get('editor')!
    const trie = buildScopeTrie([{ scope: 'org-1.team-2.repo-3', allow: 0, deny: editorBit }])
    expect(lookupScoped(t, editorBit, trie, 'org-1.team-2.repo-3', 'union', 'update', 'repo')).toBe(false)
    // No scope, or a scope with no matching deny grant: unaffected.
    expect(lookupScoped(t, editorBit, trie, undefined, 'union', 'update', 'repo')).toBe(true)
  })

  it('scope-allow widens a DYNAMIC cell past a failing condition (role-bypass fast path)', () => {
    const policies: AccessControl.IPolicy[] = [
      {
        id: 'p',
        name: 'p',
        algorithm: 'deny-overrides',
        rules: [
          {
            id: 'r',
            effect: 'allow',
            priority: 0,
            actions: ['update'],
            resources: ['repo'],
            conditions: { all: [{ field: 'resource.attributes.v', operator: 'eq', value: 1 }] },
          },
        ],
      },
    ]
    const roles: AccessControl.IRole[] = [
      { id: 'grantee', name: 'Grantee', permissions: [{ action: 'update', resource: 'repo' }] },
    ]
    const t = compileTable(roles, policies)
    const granteeBit = 1 << t.roleId.get('grantee')!
    const trie = buildScopeTrie([{ scope: 'org-1', allow: granteeBit, deny: 0 }])
    const req = {
      subject: { id: 'u', roles: [], attributes: {} },
      action: 'update',
      resource: { type: 'repo', attributes: {} },
      environment: { now: 1 },
    }
    // Base mask 0, condition fails (no attributes.v) -> would be false without scope.
    expect(lookupScoped(t, 0, trie, 'org-1.team-2', 'union', 'update', 'repo', req)).toBe(true)
  })
})
