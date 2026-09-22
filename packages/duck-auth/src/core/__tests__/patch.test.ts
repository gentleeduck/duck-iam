import { describe, expect, it } from 'vitest'
import { stripUndefined } from '~/core/patch'

describe('stripUndefined', () => {
  it('drops the keys a caller left undefined and keeps the rest, so a patch moves only what it named', () => {
    expect(stripUndefined({ emailVerified: true, profile: undefined })).toEqual({ emailVerified: true })
  })

  it('keeps a null, which names a column a caller means to clear', () => {
    expect(stripUndefined({ deletedBy: null })).toEqual({ deletedBy: null })
  })
})
