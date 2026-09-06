import { describe, expect, it } from 'vitest'
import { IamAccessClient } from '../../client/vanilla'
import { iamBuildPermissionKey, iamParsePermissionKey } from '../keys'

/**
 * "Well-formed" must mean "in the image of the builder". The splitter treats an
 * unrecognised `\x` literally - right for tokenising, but it left the parser
 * non-injective on the canonical image, so a hand-built key could parse into a
 * tuple the builder would have encoded differently. Inside one client that is a
 * live disagreement: `can()` builds a canonical key and misses, while
 * `allowedActions()` / `hasAnyOn()` parse the raw key and hit.
 */
const NON_CANONICAL = ['create:post\\', ':\\', ':@', 'a:\\', 'read:po\\st', '@org:read:@post', 'read:post:\\x']

describe('iamParsePermissionKey rejects anything outside the builder image', () => {
  it.each(NON_CANONICAL)('rejects %j', (key) => {
    expect(iamParsePermissionKey(key)).toBeNull()
  })

  // Exhaustive over a hostile alphabet: every string the parser accepts must
  // re-encode to itself.
  it('is injective on the canonical image for every key of length <= 5', () => {
    const alphabet = ['a', ':', '\\', '@', 'b']
    const offenders: string[] = []
    const walk = (prefix: string) => {
      if (prefix.length > 0) {
        const parsed = iamParsePermissionKey(prefix)
        if (parsed !== null) {
          const rebuilt = iamBuildPermissionKey(parsed.action, parsed.resource, parsed.resourceId, parsed.scope)
          if (rebuilt !== prefix) offenders.push(prefix)
        }
      }
      if (prefix.length === 5) return
      for (const ch of alphabet) walk(prefix + ch)
    }
    walk('')
    expect(offenders).toEqual([])
  })

  // Controls: everything the builder emits must still parse back.
  it.each([
    ['read', 'post', undefined, undefined],
    ['read', 'post', 'p-1', undefined],
    ['read', 'post', undefined, 'org-1'],
    ['read', 'post', 'p-1', 'org-1'],
    ['', '', '', ''],
    ['a:b', 'c\\d', '@e', 'f:g'],
  ] as const)('round-trips build(%j, %j, %j, %j)', (action, resource, resourceId, scope) => {
    const key = iamBuildPermissionKey(action, resource, resourceId, scope)
    expect(iamParsePermissionKey(key)).toEqual({ action, resource, resourceId, scope })
  })
})

/**
 * The consequence at client level: a menu shown because `hasAnyOn` is true and
 * populated from `allowedActions` rendered empty, and a raw key that `can()`
 * denies was reported as an allowed action.
 */
describe('the vanilla client agrees with itself', () => {
  it('keeps an empty-string action that hasAnyOn and can both honour', () => {
    const client = new IamAccessClient({ [iamBuildPermissionKey('', 'post')]: true })
    expect(client.can('', 'post')).toBe(true)
    expect(client.hasAnyOn('post')).toBe(true)
    expect(client.allowedActions('post')).toEqual([''])
  })

  it('does not report an action for a non-canonical key can() denies', () => {
    const client = new IamAccessClient({ 'create:post\\': true })
    expect(client.can('create', 'post\\')).toBe(false)
    expect(client.allowedActions('post\\')).toEqual([])
    expect(client.hasAnyOn('post\\')).toBe(false)
  })

  // Control: a canonically-built key for the same tuple is reported.
  it('reports the action when the key is canonical', () => {
    const client = new IamAccessClient({ [iamBuildPermissionKey('create', 'post\\')]: true })
    expect(client.can('create', 'post\\')).toBe(true)
    expect(client.allowedActions('post\\')).toEqual(['create'])
    expect(client.hasAnyOn('post\\')).toBe(true)
  })
})
