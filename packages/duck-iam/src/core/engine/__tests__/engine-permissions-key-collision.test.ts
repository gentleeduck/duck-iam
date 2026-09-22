import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

type A = 'read'
type R = 'post'
type Ro = 'viewer'
type S = 'org-1'

const viewer: AccessControl.IRole<A, R, Ro, S> = {
  id: 'viewer',
  name: 'Viewer',
  permissions: [{ action: 'read', resource: 'post' }],
}

describe('permissions() key collisions', () => {
  it('two distinct checks produce two keys even when one has an empty-string scope', async () => {
    const adapter = new IamMemoryAdapter<A, R, Ro, S>({ roles: [viewer], assignments: { u1: ['viewer'] } })
    const engine = new IamEngine<A, R, Ro, S>({ adapter, cacheTTL: 0 })
    const map = await engine.permissions('u1', [
      { action: 'read', resource: 'post' },
      { action: 'read', resource: 'post', scope: '' as S },
    ])
    expect(Object.keys(map)).toHaveLength(2)
  })
})
