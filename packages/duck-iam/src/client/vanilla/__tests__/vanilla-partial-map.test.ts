import { describe, expect, it } from 'vitest'
import { IamAccessClient } from '../index'

/**
 * The server only returns the keys that were batched. A full `PermissionMap`
 * (`Record` over every action×resource) forced callers to cast; the client
 * must accept the partial map directly, defaulting missing keys to `false`.
 */
describe('IamAccessClient partial permission map', () => {
  it('accepts a map missing some combinations without a cast', () => {
    const client = new IamAccessClient<'read' | 'write', 'post'>({ 'read:post': true })
    expect(client.can('read', 'post')).toBe(true)
    expect(client.can('write', 'post')).toBe(false)
  })

  it('defaults to an empty map', () => {
    expect(new IamAccessClient<'read', 'post'>().can('read', 'post')).toBe(false)
  })
})
