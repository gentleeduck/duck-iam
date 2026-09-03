import { describe, expect, it } from 'vitest'
import type { IamClient } from '../../core/types'
import { iamBuildPermissionKey, iamParsePermissionKey, iamSplitPermissionKey } from '../keys'

describe('iamBuildPermissionKey()', () => {
  it('action:resource', () => {
    expect(iamBuildPermissionKey('read', 'post')).toBe('read:post')
  })

  it('action:resource:resourceId', () => {
    expect(iamBuildPermissionKey('read', 'post', 'post-42')).toBe('read:post:post-42')
  })

  it('scope:action:resource', () => {
    expect(iamBuildPermissionKey('read', 'post', undefined, 'org-1')).toBe('@org-1:read:post')
  })

  it('scope:action:resource:resourceId', () => {
    expect(iamBuildPermissionKey('read', 'post', 'post-42', 'org-1')).toBe('@org-1:read:post:post-42')
  })

  it('handles empty resourceId', () => {
    expect(iamBuildPermissionKey('read', 'post', undefined)).toBe('read:post')
  })

  it('handles both scope and resourceId', () => {
    expect(iamBuildPermissionKey('update', 'post', 'p-1', 'org-1')).toBe('@org-1:update:post:p-1')
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
      expect(iamParsePermissionKey(iamBuildPermissionKey(action, resource, resourceId, scope))).toEqual({
        action,
        resource,
        resourceId,
        scope,
      })
    }
  })
})

describe('iamBuildPermissionKey - empty-string segments are real segments', () => {
  it('an empty scope does not collapse into the unscoped key', () => {
    expect(iamBuildPermissionKey('read', 'post', undefined, '')).not.toBe(iamBuildPermissionKey('read', 'post'))
    expect(iamBuildPermissionKey('read', 'post', undefined, '')).toBe('@:read:post')
  })

  it('an empty resourceId does not collapse into the type-level key', () => {
    expect(iamBuildPermissionKey('read', 'post', '')).toBe('read:post:')
  })

  it('round-trips through iamSplitPermissionKey', () => {
    expect(iamParsePermissionKey(iamBuildPermissionKey('read', 'post', undefined, ''))).toEqual({
      action: 'read',
      resource: 'post',
      resourceId: undefined,
      scope: '',
    })
    expect(iamParsePermissionKey(iamBuildPermissionKey('read', 'post', ''))).toEqual({
      action: 'read',
      resource: 'post',
      resourceId: '',
      scope: undefined,
    })
  })
})

describe('iamParsePermissionKey - arity is no longer ambiguous', () => {
  it('a scoped key and an id-bearing key never collide', () => {
    const withId = iamBuildPermissionKey('read', 'doc', '42')
    const withScope = iamBuildPermissionKey('doc', '42', undefined, 'read')
    expect(withId).not.toBe(withScope)
    expect(iamParsePermissionKey(withId)).toEqual({
      action: 'read',
      resource: 'doc',
      resourceId: '42',
      scope: undefined,
    })
    expect(iamParsePermissionKey(withScope)).toEqual({
      action: 'doc',
      resource: '42',
      resourceId: undefined,
      scope: 'read',
    })
  })

  it('an action that starts with the scope marker cannot pose as a scope', () => {
    const key = iamBuildPermissionKey('@admin', 'doc')
    expect(iamParsePermissionKey(key)).toEqual({
      action: '@admin',
      resource: 'doc',
      resourceId: undefined,
      scope: undefined,
    })
    expect(iamParsePermissionKey(key)).not.toEqual(
      iamParsePermissionKey(iamBuildPermissionKey('doc', 'x', undefined, 'admin')),
    )
  })

  it('a scope that starts with the marker round-trips', () => {
    expect(iamParsePermissionKey(iamBuildPermissionKey('read', 'doc', undefined, '@org'))?.scope).toBe('@org')
  })

  it('rejects a string that is not a key', () => {
    expect(iamParsePermissionKey('')).toBeNull()
    expect(iamParsePermissionKey('read')).toBeNull()
    expect(iamParsePermissionKey('a:b:c:d:e')).toBeNull()
  })
})

/**
 * `IamClient.PermissionKey` is the type the server->client payload is declared
 * with. It carried the pre-`@` scoped form long after the builder moved on, so
 * a consumer using literal generics - the documented pattern - could not assign
 * a real `engine.permissions()` result without a cast, while a hand-written map
 * in the retired ambiguous format type-checked clean.
 *
 * These bind the two together: each constant is annotated with the type and
 * assigned the builder's output, so a drift in either direction fails.
 */
describe('iamBuildPermissionKey() output matches IamClient.PermissionKey', () => {
  type Key = IamClient.PermissionKey<'read', 'doc', 'org'>

  it.each([
    ['read:doc', iamBuildPermissionKey('read', 'doc')],
    ['read:doc:d-1', iamBuildPermissionKey('read', 'doc', 'd-1')],
    ['@org:read:doc', iamBuildPermissionKey('read', 'doc', undefined, 'org')],
    ['@org:read:doc:d-1', iamBuildPermissionKey('read', 'doc', 'd-1', 'org')],
  ] satisfies Array<[Key, string]>)('%s', (typed, built) => {
    expect(built).toBe(typed)
  })

  // Control: `satisfies` above only checks the left column, so this pins that
  // the builder is what produced the right one.
  it('a map keyed by the builder is assignable to PartialPermissionMap', () => {
    const map: IamClient.PartialPermissionMap<'read', 'doc', 'org'> = {
      '@org:read:doc': true,
      'read:doc': false,
    }
    expect(Object.keys(map)).toContain(iamBuildPermissionKey('read', 'doc', undefined, 'org'))
  })
})
