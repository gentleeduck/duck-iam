import { describe, expect, it, vi } from 'vitest'
import type { IamClient } from '../../../core/types'
import { IamAccessClient } from '../index'

// The constructor and `update` copy the map in, so mutating it after handover changes nothing and notifies no one.
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
    // A shared map would grant with the subscriber never told, so the UI and the client would disagree.
    expect(seen).toHaveBeenCalledTimes(1)
  })

  it('a listener that mutates what it receives cannot reach the stored map', () => {
    // Listeners are handed the caller's own object, not the stored copy.
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
