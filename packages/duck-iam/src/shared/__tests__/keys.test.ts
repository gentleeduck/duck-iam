import { describe, expect, it } from 'vitest'
import { iamBuildPermissionKey } from '../keys'

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
