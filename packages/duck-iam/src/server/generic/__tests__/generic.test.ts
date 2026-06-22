import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../../core/engine'
import type { IamAccessControl } from '../../../core/types'
import {
  createIamSubjectCan,
  iamErrorToAuditString,
  iamExtractEnvironment,
  generateIamPermissionMap,
  IAM_METHOD_ACTION_MAP,
} from '../index'

type Action = 'read' | 'create' | 'update' | 'delete'
type ResourceType = 'post' | 'comment'
type RoleId = 'viewer' | 'editor'
type Scope = 'org-1'

const viewerRole: IamAccessControl.IRole<Action, ResourceType, RoleId, Scope> = {
  id: 'viewer',
  name: 'Viewer',
  permissions: [
    { action: 'read', resource: 'post' },
    { action: 'read', resource: 'comment' },
  ],
}

const editorRole: IamAccessControl.IRole<Action, ResourceType, RoleId, Scope> = {
  id: 'editor',
  name: 'Editor',
  inherits: ['viewer'],
  permissions: [
    { action: 'create', resource: 'post' },
    { action: 'update', resource: 'post' },
  ],
}

function createEngine() {
  const adapter = new IamMemoryAdapter<Action, ResourceType, RoleId, Scope>({
    roles: [viewerRole, editorRole],
    assignments: {
      'user-viewer': ['viewer'],
      'user-editor': ['editor'],
    },
  })
  return new IamEngine<Action, ResourceType, RoleId, Scope>({ adapter, cacheTTL: 0 })
}

describe('generateIamPermissionMap()', () => {
  it('generates a permission map for a subject', async () => {
    const engine = createEngine()
    const map = await generateIamPermissionMap(engine, 'user-viewer', [
      { action: 'read', resource: 'post' },
      { action: 'create', resource: 'post' },
    ])
    expect(map['read:post']).toBe(true)
    expect(map['create:post']).toBe(false)
  })

  it('generates correct map for editor', async () => {
    const engine = createEngine()
    const map = await generateIamPermissionMap(engine, 'user-editor', [
      { action: 'read', resource: 'post' },
      { action: 'create', resource: 'post' },
      { action: 'update', resource: 'post' },
      { action: 'delete', resource: 'post' },
    ])
    expect(map['read:post']).toBe(true)
    expect(map['create:post']).toBe(true)
    expect(map['update:post']).toBe(true)
    expect(map['delete:post']).toBe(false)
  })
})

describe('createIamSubjectCan()', () => {
  it('returns a function that checks permissions', async () => {
    const engine = createEngine()
    const can = createIamSubjectCan(engine, 'user-viewer')

    expect(await can('read', 'post')).toBe(true)
    expect(await can('create', 'post')).toBe(false)
  })

  it('supports resourceId parameter', async () => {
    const engine = createEngine()
    const can = createIamSubjectCan(engine, 'user-viewer')

    expect(await can('read', 'post', 'post-42')).toBe(true)
  })
})

describe('iamExtractEnvironment()', () => {
  it('extracts IP and user agent from request object', () => {
    const env = iamExtractEnvironment({
      ip: '192.168.1.1',
      headers: { 'user-agent': 'Mozilla/5.0' },
    })
    expect(env.ip).toBe('192.168.1.1')
    expect(env.userAgent).toBe('Mozilla/5.0')
    expect(env.timestamp).toBeGreaterThan(0)
  })

  it('falls back to x-forwarded-for header', () => {
    const env = iamExtractEnvironment({
      headers: { 'x-forwarded-for': '10.0.0.1' },
    })
    expect(env.ip).toBe('10.0.0.1')
  })

  it('falls back to x-real-ip header', () => {
    const env = iamExtractEnvironment({
      headers: { 'x-real-ip': '10.0.0.2' },
    })
    expect(env.ip).toBe('10.0.0.2')
  })

  it('handles Headers object', () => {
    const headers = new Headers()
    headers.set('user-agent', 'TestAgent')
    headers.set('x-forwarded-for', '10.0.0.3')

    const env = iamExtractEnvironment({ headers })
    expect(env.userAgent).toBe('TestAgent')
    expect(env.ip).toBe('10.0.0.3')
  })

  it('handles missing headers gracefully', () => {
    const env = iamExtractEnvironment({})
    expect(env.ip).toBeUndefined()
    expect(env.userAgent).toBeUndefined()
  })

  it('handles array header values', () => {
    const env = iamExtractEnvironment({
      headers: { 'x-forwarded-for': ['10.0.0.1', '10.0.0.2'] },
    })
    expect(env.ip).toBe('10.0.0.1')
  })
})

describe('IAM_METHOD_ACTION_MAP', () => {
  it('maps GET to read', () => {
    expect(IAM_METHOD_ACTION_MAP.GET).toBe('read')
  })

  it('maps POST to create', () => {
    expect(IAM_METHOD_ACTION_MAP.POST).toBe('create')
  })

  it('maps PUT and PATCH to update', () => {
    expect(IAM_METHOD_ACTION_MAP.PUT).toBe('update')
    expect(IAM_METHOD_ACTION_MAP.PATCH).toBe('update')
  })

  it('maps DELETE to delete', () => {
    expect(IAM_METHOD_ACTION_MAP.DELETE).toBe('delete')
  })

  it('maps HEAD and OPTIONS to read', () => {
    expect(IAM_METHOD_ACTION_MAP.HEAD).toBe('read')
    expect(IAM_METHOD_ACTION_MAP.OPTIONS).toBe('read')
  })
})

describe('iamErrorToAuditString', () => {
  it('returns class name when includeMessage is omitted (default safe)', () => {
    expect(iamErrorToAuditString(new TypeError('boom'))).toBe('TypeError')
  })

  it('returns Error.message when includeMessage is true', () => {
    expect(iamErrorToAuditString(new Error('explicit'), true)).toBe('explicit')
  })

  it('tags non-Error throws + caps length when includeMessage is true', () => {
    const longSecret = 'X'.repeat(2000)
    const out = iamErrorToAuditString(longSecret, true)
    expect(out.startsWith('<non-Error string>')).toBe(true)
    expect(out).toContain('XXX')
    expect(out.length).toBeLessThan(500)
  })

  it('JSON.stringifies plain object non-Errors when includeMessage is true', () => {
    expect(iamErrorToAuditString({ kind: 'wrapper' }, true)).toBe('<non-Error object> {"kind":"wrapper"}')
  })

  it('falls back to String() on circular references', () => {
    const circ: Record<string, unknown> = {}
    circ.self = circ
    const out = iamErrorToAuditString(circ, true)
    expect(out.startsWith('<non-Error object>')).toBe(true)
    expect(out).toContain('[object Object]')
  })

  it('safe defaults for undefined / null', () => {
    expect(iamErrorToAuditString(undefined)).toBe('undefined')
    expect(iamErrorToAuditString(null)).toBe('null')
    expect(iamErrorToAuditString(undefined, true)).toBe('undefined')
    expect(iamErrorToAuditString(null, true)).toBe('null')
  })
})
