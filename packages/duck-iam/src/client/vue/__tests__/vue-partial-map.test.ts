import { describe, expectTypeOf, it } from 'vitest'
import type { IamClient } from '../../../core/types'
import type { createIamVueAccess } from '../index'

/** Vue's `createAccessState`/`provideAccess`/`createAccessPlugin` take the same partial map React does. */
type Access = ReturnType<typeof createIamVueAccess<'read' | 'write', 'post'>>

describe('createIamVueAccess partial permission map', () => {
  it('accepts a map missing some combinations', () => {
    expectTypeOf<Parameters<Access['createAccessState']>[0]>().toEqualTypeOf<
      IamClient.PartialPermissionMap<'read' | 'write', 'post'>
    >()
    expectTypeOf<Parameters<Access['provideAccess']>[0]>().toEqualTypeOf<
      IamClient.PartialPermissionMap<'read' | 'write', 'post'>
    >()
    expectTypeOf<Parameters<Access['createAccessPlugin']>[0]>().toEqualTypeOf<
      IamClient.PartialPermissionMap<'read' | 'write', 'post'>
    >()
    expectTypeOf({ 'read:post': true } as const).toMatchTypeOf<Parameters<Access['createAccessState']>[0]>()
  })
})
