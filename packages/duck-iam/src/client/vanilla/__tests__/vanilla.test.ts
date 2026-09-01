import { afterEach, describe, expect, it, vi } from 'vitest'
import type { IamClient } from '../../../core/types'
import { IamAccessClient, iamAccessClient } from '../index'

type Action = 'read' | 'create' | 'update' | 'delete'
type ResourceType = 'post' | 'comment'
type Scope = 'org-1'

/** Cast a plain permission record to the typed IamClient.PermissionMap. */
function perms(map: Record<string, boolean>): IamClient.PermissionMap<Action, ResourceType, Scope> {
  return map as IamClient.PermissionMap<Action, ResourceType, Scope>
}

describe('IamAccessClient', () => {
  it('can() returns true for allowed permissions', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(perms({ 'read:post': true, 'create:post': false }))
    expect(client.can('read', 'post')).toBe(true)
    expect(client.can('create', 'post')).toBe(false)
  })

  it('can() returns false for unknown permissions', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(perms({}))
    expect(client.can('read', 'post')).toBe(false)
  })

  it('cannot() is the negation of can()', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(perms({ 'read:post': true }))
    expect(client.cannot('read', 'post')).toBe(false)
    expect(client.cannot('create', 'post')).toBe(true)
  })

  it('can() works with scoped keys', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(perms({ 'org-1:read:post': true }))
    expect(client.can('read', 'post', undefined, 'org-1')).toBe(true)
  })

  it('can() works with resourceId keys', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(perms({ 'read:post:post-42': true }))
    expect(client.can('read', 'post', 'post-42')).toBe(true)
  })

  it('permissions getter returns the permissions map', () => {
    const p = perms({ 'read:post': true })
    const client = new IamAccessClient<Action, ResourceType, Scope>(p)
    expect(client.permissions).toEqual(p)
  })

  it('defaults to empty permissions when none provided', () => {
    const client = new IamAccessClient()
    expect(client.permissions).toEqual({})
  })

  it('update() replaces permissions and notifies subscribers', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(perms({}))
    const listener = vi.fn()
    client.subscribe(listener)

    const newPerms = perms({ 'read:post': true })
    client.update(newPerms)

    expect(client.can('read', 'post')).toBe(true)
    expect(listener).toHaveBeenCalledWith(newPerms)
  })

  it('merge() merges new permissions into existing', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(perms({ 'read:post': true }))
    client.merge(perms({ 'create:post': true }))
    expect(client.can('read', 'post')).toBe(true)
    expect(client.can('create', 'post')).toBe(true)
  })

  it('subscribe() returns an unsubscribe function', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(perms({}))
    const listener = vi.fn()
    const unsub = client.subscribe(listener)

    client.update(perms({ 'read:post': true }))
    expect(listener).toHaveBeenCalledTimes(1)

    unsub()
    client.update(perms({ 'read:post': false }))
    expect(listener).toHaveBeenCalledTimes(1) // not called again
  })

  it('allowedActions() returns exact allowed actions for a resource', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(
      perms({ 'read:post': true, 'create:post': true, 'delete:post': false, 'read:comment': true }),
    )
    const actions = client.allowedActions('post')
    expect(actions).toEqual(expect.arrayContaining(['read', 'create']))
    expect(actions).toHaveLength(2)
    expect(actions).not.toContain('delete')
  })

  it('allowedActions() handles scoped keys', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(
      perms({ 'org-1:read:post': true, 'org-1:create:post': true }),
    )
    const actions = client.allowedActions('post')
    expect(actions).toEqual(expect.arrayContaining(['read', 'create']))
    expect(actions).toHaveLength(2)
  })

  it('allowedActions() honours escape sequences for resources containing :', () => {
    // Resource 'doc:42' is keyed as 'read:doc\\:42'. Naive split-on-:
    // would mis-tokenise; iamSplitPermissionKey unescapes correctly.
    const client = new IamAccessClient<Action, ResourceType, Scope>(
      perms({ 'read:doc\\:42': true, 'create:doc\\:42': true }),
    )
    const actions = client.allowedActions('doc:42' as never)
    expect(actions).toEqual(expect.arrayContaining(['read', 'create']))
    expect(actions).toHaveLength(2)
  })

  it('allowedActions() deduplicates actions', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(
      perms({ 'read:post': true, 'org-1:read:post': true }),
    )
    const actions = client.allowedActions('post')
    expect(actions).toEqual(['read'])
  })

  it('hasAnyOn() returns true when any permission exists on resource', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(perms({ 'read:post': true }))
    expect(client.hasAnyOn('post')).toBe(true)
    expect(client.hasAnyOn('comment')).toBe(false)
  })

  it('hasAnyOn() returns false when all permissions are false', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(perms({ 'read:post': false, 'create:post': false }))
    expect(client.hasAnyOn('post')).toBe(false)
  })

  it('listener errors do not prevent other listeners from firing', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(perms({}))
    const results: string[] = []
    client.subscribe(() => {
      results.push('first')
      throw new Error('boom')
    })
    client.subscribe(() => {
      results.push('second')
    })

    client.update(perms({ 'read:post': true }))
    expect(results).toEqual(['first', 'second'])
  })
})
describe('IamAccessClient.fromServer', () => {
  const originalFetch = globalThis.fetch

  afterEach(() => {
    globalThis.fetch = originalFetch
  })

  it('returns a populated client from a 2xx JSON body', async () => {
    globalThis.fetch = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ 'read:post': true }),
    })) as unknown as typeof fetch

    const client = await IamAccessClient.fromServer<Action, ResourceType, Scope>('/api/permissions')
    expect(client).toBeInstanceOf(IamAccessClient)
    expect(client.can('read', 'post')).toBe(true)
    expect(client.can('create', 'post')).toBe(false)
  })

  it('sends Content-Type json and merges caller headers and init', async () => {
    const spy = vi.fn(async () => ({ ok: true, status: 200, json: async () => ({}) }))
    globalThis.fetch = spy as unknown as typeof fetch

    await IamAccessClient.fromServer('/api/permissions', {
      headers: { Authorization: 'Bearer t' },
      method: 'POST',
    })

    const [url, init] = spy.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('/api/permissions')
    expect(init.method).toBe('POST')
    expect(init.headers).toEqual({ 'Content-Type': 'application/json', Authorization: 'Bearer t' })
  })

  it('lets the caller override Content-Type', async () => {
    const spy = vi.fn(async () => ({ ok: true, status: 200, json: async () => ({}) }))
    globalThis.fetch = spy as unknown as typeof fetch

    await IamAccessClient.fromServer('/api/permissions', { headers: { 'Content-Type': 'text/plain' } })

    const [, init] = spy.mock.calls[0] as unknown as [string, RequestInit]
    expect(init.headers).toEqual({ 'Content-Type': 'text/plain' })
  })

  it('throws with the status code on a non-2xx response', async () => {
    globalThis.fetch = vi.fn(async () => ({
      ok: false,
      status: 403,
      json: async () => ({}),
    })) as unknown as typeof fetch

    await expect(IamAccessClient.fromServer('/api/permissions')).rejects.toThrow('Failed to fetch permissions: 403')
  })

  it('does not read the body when the response is not ok', async () => {
    const json = vi.fn(async () => ({}))
    globalThis.fetch = vi.fn(async () => ({ ok: false, status: 500, json })) as unknown as typeof fetch

    await expect(IamAccessClient.fromServer('/api/permissions')).rejects.toThrow()
    expect(json).not.toHaveBeenCalled()
  })
})

describe('iamAccessClient factory', () => {
  it('builds an IamAccessClient equivalent to the constructor', () => {
    const client = iamAccessClient({ 'read:post': true })
    expect(client).toBeInstanceOf(IamAccessClient)
    expect(client.can('read', 'post')).toBe(true)
    expect(client.can('create', 'post')).toBe(false)
  })

  it('defaults to empty permissions when called with no arguments', () => {
    expect(iamAccessClient().permissions).toEqual({})
  })
})

describe('allowedActions / hasAnyOn key-shape edges', () => {
  it('ignores keys with fewer than 2 or more than 4 segments', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(
      perms({ post: true, 'a:b:c:d:post': true, 'read:post': true }),
    )
    expect(client.allowedActions('post')).toEqual(['read'])
  })

  it('resolves a 4-segment scope:action:resource:resourceId key', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(perms({ 'org-1:read:post:post-9': true }))
    expect(client.allowedActions('post')).toEqual(['read'])
    expect(client.hasAnyOn('post')).toBe(true)
  })

  it('does not treat a 4-segment resourceId as the resource', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(perms({ 'org-1:read:comment:post': true }))
    expect(client.allowedActions('post')).toEqual([])
    expect(client.hasAnyOn('post')).toBe(false)
  })

  it('returns an empty list for a resource with no keys at all', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(perms({}))
    expect(client.allowedActions('post')).toEqual([])
    expect(client.hasAnyOn('post')).toBe(false)
  })

  it('merge() notifies subscribers with the merged map', () => {
    const client = new IamAccessClient<Action, ResourceType, Scope>(perms({ 'read:post': true }))
    const listener = vi.fn()
    client.subscribe(listener)
    client.merge(perms({ 'create:post': true }))
    expect(listener).toHaveBeenCalledWith({ 'read:post': true, 'create:post': true })
  })
})
