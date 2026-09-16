import { describe, expect, it, vi } from 'vitest'
import type { IamClient } from '../../../core/types'
import { IamAccessClient } from '../index'

type A = 'read' | 'create' | 'delete' | ''
type R = 'post' | 'comment'
type S = 'org-1'

// Only a literal `true` grants, and `can`, `allowedActions`, and `hasAnyOn` must agree on that.
describe('vanilla client: a non-boolean map value denies', () => {
  // Built the way a hostile map actually arrives: unvalidated server JSON.
  const hostile: IamClient.PartialPermissionMap<A, R, S> = JSON.parse(
    '{"read:post":"false","create:post":1,"delete:post":"true"}',
  )

  it('can() denies each of them', () => {
    const c = new IamAccessClient<A, R, S>(hostile)
    expect(c.can('read', 'post')).toBe(false)
    expect(c.can('create', 'post')).toBe(false)
    expect(c.can('delete', 'post')).toBe(false)
  })

  it('allowedActions() lists none of them', () => {
    expect(new IamAccessClient<A, R, S>(hostile).allowedActions('post')).toEqual([])
  })

  it('hasAnyOn() is false', () => {
    expect(new IamAccessClient<A, R, S>(hostile).hasAnyOn('post')).toBe(false)
  })

  // Control: a literal `true` grants through all three readers.
  it('a literal true grants through every reader', () => {
    const c = new IamAccessClient<A, R, S>({ 'read:post': true })
    expect(c.can('read', 'post')).toBe(true)
    expect(c.allowedActions('post')).toEqual(['read'])
    expect(c.hasAnyOn('post')).toBe(true)
  })
})

// `iamBuildPermissionKey` treats `''` as a real segment, so all three readers must.
describe('vanilla client: an empty-string action', () => {
  const c = new IamAccessClient<A, R, S>({ ':post': true })

  it('can() honours it', () => {
    expect(c.can('', 'post')).toBe(true)
  })

  it('allowedActions() keeps it', () => {
    expect(c.allowedActions('post')).toEqual([''])
  })

  it('hasAnyOn() agrees with allowedActions()', () => {
    expect(c.hasAnyOn('post')).toBe(true)
  })
})

// `Readonly` erases at runtime, so a live map would let an edit grant without `update()` or a notification.
describe('vanilla client: the permissions getter is a copy', () => {
  function grantInto(map: unknown, key: string): void {
    if (typeof map === 'object' && map !== null) Reflect.set(map, key, true)
  }

  it('mutating the view does not grant', () => {
    const c = new IamAccessClient<A, R, S>({ 'read:post': true })
    grantInto(c.permissions, 'delete:post')
    expect(c.can('delete', 'post')).toBe(false)
  })

  it('mutating the view does not skip subscribers', () => {
    const c = new IamAccessClient<A, R, S>({ 'read:post': true })
    const listener = vi.fn()
    c.subscribe(listener)
    grantInto(c.permissions, 'delete:post')
    expect(listener).not.toHaveBeenCalled()
  })

  it('hands out a fresh object each read', () => {
    const c = new IamAccessClient<A, R, S>({ 'read:post': true })
    expect(c.permissions).not.toBe(c.permissions)
  })

  // Control: the copy carries the real contents, and `update()` still works.
  it('reflects the current map and notifies through update()', () => {
    const c = new IamAccessClient<A, R, S>({ 'read:post': true })
    const listener = vi.fn()
    c.subscribe(listener)
    expect(c.permissions).toEqual({ 'read:post': true })
    c.update({ 'delete:post': true })
    expect(c.can('delete', 'post')).toBe(true)
    expect(listener).toHaveBeenCalled()
  })
})
