import { describe, expect, it } from 'vitest'
import { iamBuildPermissionKey } from '../keys'
import { iamAllowedActions, iamHasAnyOn, iamPermissionGranted } from '../permission-map'

// The two summaries filter on resource alone, so a grant held only in one scope or on one record still
// appears in them. `can()` builds the whole key and does not. Pinned so a change to either is deliberate.

const SCOPED = { [iamBuildPermissionKey('delete', 'post', undefined, 'org-1')]: true }
const PER_RECORD = { [iamBuildPermissionKey('read', 'post', '42')]: true }

describe('allowedActions and hasAnyOn ignore scope and record id; can() does not', () => {
  it('control: an unscoped grant on the resource is listed and readable by key', () => {
    const map = { [iamBuildPermissionKey('read', 'post')]: true }
    expect(iamAllowedActions(map, 'post')).toEqual(['read'])
    expect(iamPermissionGranted(map, iamBuildPermissionKey('read', 'post'))).toBe(true)
  })

  it('lists an action granted only inside a scope, which the unscoped key lookup denies', () => {
    expect(iamAllowedActions(SCOPED, 'post')).toEqual(['delete'])
    expect(iamHasAnyOn(SCOPED, 'post')).toBe(true)
    expect(iamPermissionGranted(SCOPED, iamBuildPermissionKey('delete', 'post'))).toBe(false)
  })

  it('lists an action granted only on one record, which the record-free key lookup denies', () => {
    expect(iamAllowedActions(PER_RECORD, 'post')).toEqual(['read'])
    expect(iamHasAnyOn(PER_RECORD, 'post')).toBe(true)
    expect(iamPermissionGranted(PER_RECORD, iamBuildPermissionKey('read', 'post'))).toBe(false)
  })

  it('the same action scoped and unscoped is listed once, so the summary cannot say which one it saw', () => {
    const map = {
      [iamBuildPermissionKey('read', 'post')]: true,
      [iamBuildPermissionKey('read', 'post', undefined, 'org-1')]: true,
    }
    expect(iamAllowedActions(map, 'post')).toEqual(['read'])
  })

  it('a denied scoped grant is not listed, so it is the value that decides, not the shape of the key', () => {
    const map = { [iamBuildPermissionKey('delete', 'post', undefined, 'org-1')]: false }
    expect(iamAllowedActions(map, 'post')).toEqual([])
    expect(iamHasAnyOn(map, 'post')).toBe(false)
  })

  it('another resource under the same scope is not listed', () => {
    expect(iamAllowedActions(SCOPED, 'comment')).toEqual([])
    expect(iamHasAnyOn(SCOPED, 'comment')).toBe(false)
  })
})
