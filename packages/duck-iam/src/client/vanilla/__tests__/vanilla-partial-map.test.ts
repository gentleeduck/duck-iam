import { describe, expect, it } from 'vitest'
import { IamAccessClient } from '../index'

// The server returns only the batched keys, so the client takes a partial map and denies missing keys.
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
