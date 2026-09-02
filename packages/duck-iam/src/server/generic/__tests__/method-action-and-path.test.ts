import { describe, expect, it } from 'vitest'
import {
  IAM_UNKNOWN_ACTION,
  IAM_UNKNOWN_RESOURCE,
  iamActionForMethod,
  iamDefaultResource,
  iamNormalizePathname,
} from '../index'

describe('iamActionForMethod', () => {
  it('maps the standard methods', () => {
    expect(iamActionForMethod('GET')).toBe('read')
    expect(iamActionForMethod('POST')).toBe('create')
    expect(iamActionForMethod('PUT')).toBe('update')
    expect(iamActionForMethod('PATCH')).toBe('update')
    expect(iamActionForMethod('DELETE')).toBe('delete')
  })

  it('is case-insensitive, so a lowercase DELETE is not authorized as a read', () => {
    expect(iamActionForMethod('delete')).toBe('delete')
    expect(iamActionForMethod('Post')).toBe('create')
  })

  it('an unmapped method gets a sentinel action, not read', () => {
    expect(iamActionForMethod('PURGE')).toBe(IAM_UNKNOWN_ACTION)
    expect(iamActionForMethod('')).toBe(IAM_UNKNOWN_ACTION)
    expect(iamActionForMethod(undefined)).toBe(IAM_UNKNOWN_ACTION)
  })
})

describe('iamNormalizePathname', () => {
  it.each([
    ['/admin', '/admin'],
    ['//admin', '/admin'],
    ['///admin', '/admin'],
    ['/%61dmin', '/admin'],
    ['/%2E%2E/admin', '/admin'],
    ['/./admin', '/admin'],
    ['/a/../admin', '/admin'],
    ['/admin/', '/admin/'],
    ['/', '/'],
  ])('normalizes %s to %s', (input, expected) => {
    expect(iamNormalizePathname(input)).toBe(expected)
  })

  it('keeps the raw path when the escape is malformed', () => {
    expect(iamNormalizePathname('/%zz')).toBe('/%zz')
  })

  it('cannot escape above the root', () => {
    expect(iamNormalizePathname('/../../etc/passwd')).toBe('/etc/passwd')
  })

  it('every encoded variant of /admin matches a /admin prefix rule', () => {
    for (const variant of ['//admin', '/%61dmin', '/./admin', '/x/../admin']) {
      expect(iamNormalizePathname(variant).startsWith('/admin')).toBe(true)
    }
  })
})

describe('iamDefaultResource', () => {
  it('reads type and id from a plain path', () => {
    expect(iamDefaultResource('/posts/42')).toEqual({ attributes: {}, id: '42', type: 'posts' })
  })

  it('an empty path is the root resource', () => {
    expect(iamDefaultResource('/').type).toBe('root')
    expect(iamDefaultResource(undefined).type).toBe('root')
  })

  it('traversal cannot make /admin/secret look like a posts read', () => {
    expect(iamDefaultResource('/posts/../admin/secret').type).toBe('admin')
    expect(iamDefaultResource('/posts/%2e%2e/admin/secret').type).toBe('admin')
  })

  it('a double-encoded segment falls back to the unmatched sentinel', () => {
    expect(iamDefaultResource('/posts/%252e%252e/admin').type).toBe(IAM_UNKNOWN_RESOURCE)
  })
})
