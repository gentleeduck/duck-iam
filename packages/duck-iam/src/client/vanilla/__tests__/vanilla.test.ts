import { describe, expect, it, vi } from 'vitest'
import { AccessClient } from '../index'

type Action = 'read' | 'create' | 'update' | 'delete'
type Resource = 'post' | 'comment'
type Scope = 'org-1'

describe('AccessClient', () => {
  it('can() returns true for allowed permissions', () => {
    const client = new AccessClient<Action, Resource, Scope>({
      'read:post': true,
      'create:post': false,
    } as any)
    expect(client.can('read', 'post')).toBe(true)
    expect(client.can('create', 'post')).toBe(false)
  })

  it('can() returns false for unknown permissions', () => {
    const client = new AccessClient<Action, Resource, Scope>({} as any)
    expect(client.can('read', 'post')).toBe(false)
  })

  it('cannot() is the negation of can()', () => {
    const client = new AccessClient<Action, Resource, Scope>({
      'read:post': true,
    } as any)
    expect(client.cannot('read', 'post')).toBe(false)
    expect(client.cannot('create', 'post')).toBe(true)
  })

  it('can() works with scoped keys', () => {
    const client = new AccessClient<Action, Resource, Scope>({
      'org-1:read:post': true,
    } as any)
    expect(client.can('read', 'post', undefined, 'org-1')).toBe(true)
  })

  it('can() works with resourceId keys', () => {
    const client = new AccessClient<Action, Resource, Scope>({
      'read:post:post-42': true,
    } as any)
    expect(client.can('read', 'post', 'post-42')).toBe(true)
  })

  it('permissions getter returns the permissions map', () => {
    const perms = { 'read:post': true } as any
    const client = new AccessClient<Action, Resource, Scope>(perms)
    expect(client.permissions).toEqual(perms)
  })

  it('defaults to empty permissions when none provided', () => {
    const client = new AccessClient()
    expect(client.permissions).toEqual({})
  })

  it('update() replaces permissions and notifies subscribers', () => {
    const client = new AccessClient<Action, Resource, Scope>({} as any)
    const listener = vi.fn()
    client.subscribe(listener)

    const newPerms = { 'read:post': true } as any
    client.update(newPerms)

    expect(client.can('read', 'post')).toBe(true)
    expect(listener).toHaveBeenCalledWith(newPerms)
  })

  it('merge() merges new permissions into existing', () => {
    const client = new AccessClient<Action, Resource, Scope>({
      'read:post': true,
    } as any)
    client.merge({ 'create:post': true } as any)
    expect(client.can('read', 'post')).toBe(true)
    expect(client.can('create', 'post')).toBe(true)
  })

  it('subscribe() returns an unsubscribe function', () => {
    const client = new AccessClient<Action, Resource, Scope>({} as any)
    const listener = vi.fn()
    const unsub = client.subscribe(listener)

    client.update({ 'read:post': true } as any)
    expect(listener).toHaveBeenCalledTimes(1)

    unsub()
    client.update({ 'read:post': false } as any)
    expect(listener).toHaveBeenCalledTimes(1) // not called again
  })

  it('allowedActions() returns actions for a resource', () => {
    const client = new AccessClient<Action, Resource, Scope>({
      'read:post': true,
      'create:post': true,
      'delete:post': false,
      'read:comment': true,
    } as any)
    const actions = client.allowedActions('post')
    expect(actions).toContain('read')
    expect(actions).toContain('create')
    expect(actions).not.toContain('delete')
  })

  it('allowedActions() handles scoped keys', () => {
    const client = new AccessClient<Action, Resource, Scope>({
      'org-1:read:post': true,
      'org-1:create:post': true,
    } as any)
    const actions = client.allowedActions('post')
    expect(actions).toContain('read')
    expect(actions).toContain('create')
  })

  it('allowedActions() deduplicates actions', () => {
    const client = new AccessClient<Action, Resource, Scope>({
      'read:post': true,
      'org-1:read:post': true,
    } as any)
    const actions = client.allowedActions('post')
    const readCount = actions.filter((a) => a === 'read').length
    expect(readCount).toBe(1)
  })

  it('hasAnyOn() returns true when any permission exists on resource', () => {
    const client = new AccessClient<Action, Resource, Scope>({
      'read:post': true,
    } as any)
    expect(client.hasAnyOn('post')).toBe(true)
    expect(client.hasAnyOn('comment')).toBe(false)
  })

  it('hasAnyOn() returns false when all permissions are false', () => {
    const client = new AccessClient<Action, Resource, Scope>({
      'read:post': false,
      'create:post': false,
    } as any)
    expect(client.hasAnyOn('post')).toBe(false)
  })
})
