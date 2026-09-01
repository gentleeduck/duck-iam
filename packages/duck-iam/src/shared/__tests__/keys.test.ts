import { describe, expect, it } from 'vitest'
import { iamBuildPermissionKey, iamSplitPermissionKey } from '../keys'

describe('iamBuildPermissionKey()', () => {
  it('action:resource', () => {
    expect(iamBuildPermissionKey('read', 'post')).toBe('read:post')
  })

  it('action:resource:resourceId', () => {
    expect(iamBuildPermissionKey('read', 'post', 'post-42')).toBe('read:post:post-42')
  })

  it('scope:action:resource', () => {
    expect(iamBuildPermissionKey('read', 'post', undefined, 'org-1')).toBe('org-1:read:post')
  })

  it('scope:action:resource:resourceId', () => {
    expect(iamBuildPermissionKey('read', 'post', 'post-42', 'org-1')).toBe('org-1:read:post:post-42')
  })

  it('handles empty resourceId', () => {
    expect(iamBuildPermissionKey('read', 'post', undefined)).toBe('read:post')
  })

  it('handles both scope and resourceId', () => {
    expect(iamBuildPermissionKey('update', 'post', 'p-1', 'org-1')).toBe('org-1:update:post:p-1')
  })

  it('escapes `:` in segments so action "post:read" does not collide', () => {
    // Segments containing `:` are escaped (`:` -> `\:`) so two structurally
    // different inputs map to two distinct keys.
    const a = iamBuildPermissionKey('post:read', 'post')
    const b = iamBuildPermissionKey('post', 'read:post')
    expect(a).not.toBe(b)
    expect(a).toBe('post\\:read:post')
    expect(b).toBe('post:read\\:post')
  })

  it('escapes `\\` in segments to keep the escape sequence unambiguous', () => {
    expect(iamBuildPermissionKey('a\\b', 'c')).toBe('a\\\\b:c')
  })
})

describe('iamSplitPermissionKey()', () => {
  it('splits a plain key', () => {
    expect(iamSplitPermissionKey('read:post')).toEqual(['read', 'post'])
  })

  it('splits a scoped key with a resourceId', () => {
    expect(iamSplitPermissionKey('org-1:update:post:p-1')).toEqual(['org-1', 'update', 'post', 'p-1'])
  })

  it('unescapes `\\:` back to a literal `:` instead of splitting on it', () => {
    expect(iamSplitPermissionKey('post\\:read:post')).toEqual(['post:read', 'post'])
  })

  it('unescapes `\\\\` back to a single backslash', () => {
    expect(iamSplitPermissionKey('a\\\\b:c')).toEqual(['a\\b', 'c'])
  })

  it('leaves an unrecognised escape sequence literal', () => {
    // `\x` must not silently become `x` - an attacker could otherwise craft a
    // key that unescapes onto a different permission.
    expect(iamSplitPermissionKey('a\\xb')).toEqual(['a\\xb'])
  })

  it('keeps a trailing lone backslash literal', () => {
    expect(iamSplitPermissionKey('a\\')).toEqual(['a\\'])
  })

  it('preserves empty segments', () => {
    expect(iamSplitPermissionKey('a::b')).toEqual(['a', '', 'b'])
    expect(iamSplitPermissionKey('')).toEqual([''])
  })

  it('round-trips every iamBuildPermissionKey shape', () => {
    const cases: [string, string, string | undefined, string | undefined][] = [
      ['read', 'post', undefined, undefined],
      ['read', 'post', 'p-1', undefined],
      ['read', 'post', undefined, 'org-1'],
      ['read', 'post', 'p-1', 'org-1'],
      ['post:read', 'a\\b', 'p:1', 'org\\:1'],
    ]
    for (const [action, resource, resourceId, scope] of cases) {
      const expected = [scope, action, resource, resourceId].filter((s): s is string => s !== undefined)
      expect(iamSplitPermissionKey(iamBuildPermissionKey(action, resource, resourceId, scope))).toEqual(expected)
    }
  })
})

describe('iamBuildPermissionKey - empty-string segments are real segments', () => {
  it('an empty scope does not collapse into the unscoped key', () => {
    expect(iamBuildPermissionKey('read', 'post', undefined, '')).not.toBe(iamBuildPermissionKey('read', 'post'))
    expect(iamBuildPermissionKey('read', 'post', undefined, '')).toBe(':read:post')
  })

  it('an empty resourceId does not collapse into the type-level key', () => {
    expect(iamBuildPermissionKey('read', 'post', '')).toBe('read:post:')
  })

  it('round-trips through iamSplitPermissionKey', () => {
    expect(iamSplitPermissionKey(iamBuildPermissionKey('read', 'post', undefined, ''))).toEqual(['', 'read', 'post'])
    expect(iamSplitPermissionKey(iamBuildPermissionKey('read', 'post', ''))).toEqual(['read', 'post', ''])
  })
})
