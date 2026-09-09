import { describe, expect, it, vi } from 'vitest'
import type { IamClient } from '../../../core/types'
import { IamAccessClient } from '../index'

/**
 * The `permissions` getter has always returned a copy, and its docblock says
 * why: `Readonly<...>` erases at runtime, so handing out the internal map lets
 * an in-place edit grant a permission without going through `update()` /
 * `merge()` - and therefore without notifying a single subscriber.
 *
 * The same hazard existed on the way *in*, where nothing guarded it. The
 * constructor and `update` stored the caller's reference, so a map mutated
 * after being handed over changed what `can()` answered, silently and with no
 * listener notified. Sharing one map object across a client and the code that
 * built it is not exotic - it is what "fetch it once and pass it around" looks
 * like.
 */
const grant = (map: Record<string, boolean>): IamClient.PartialPermissionMap => map

describe('the client owns its permission map', () => {
  it('a map mutated after construction does not grant anything', () => {
    const map = grant({ 'read:post': true })
    const access = new IamAccessClient(map)
    expect(access.can('read', 'post')).toBe(true)

    map['delete:post'] = true
    expect(access.can('delete', 'post')).toBe(false)
  })

  it('a map mutated after update() does not grant anything, and no listener is skipped', () => {
    const access = new IamAccessClient()
    const seen = vi.fn()
    access.subscribe(seen)

    const map = grant({ 'read:post': true })
    access.update(map)
    expect(seen).toHaveBeenCalledTimes(1)

    map['delete:post'] = true
    expect(access.can('delete', 'post')).toBe(false)
    // The silent part is the point: the grant would have taken effect with the
    // subscriber never told, so a rendered UI and the client would disagree.
    expect(seen).toHaveBeenCalledTimes(1)
  })

  it('a listener that mutates what it receives cannot reach the stored map', () => {
    // Listeners are handed the caller's own object, not the stored copy - what
    // a listener does to it is between the listener and the caller.
    const access = new IamAccessClient()
    access.subscribe((perms) => {
      Reflect.set(perms, 'delete:post', true)
    })
    access.update(grant({ 'read:post': true }))
    expect(access.can('delete', 'post')).toBe(false)
  })

  it('merge still composes onto what is already stored', () => {
    const access = new IamAccessClient(grant({ 'read:post': true }))
    access.merge(grant({ 'delete:post': true }))
    expect(access.can('read', 'post')).toBe(true)
    expect(access.can('delete', 'post')).toBe(true)
  })
})
