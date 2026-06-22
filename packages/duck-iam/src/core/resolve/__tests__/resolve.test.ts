import { describe, expect, it } from 'vitest'
import type { IamRequest } from '../../types'
import { iamMatchesAction, iamMatchesResource, iamMatchesResourceHierarchical, iamMatchesScope, iamResolve } from '../resolve'

const baseRequest: IamRequest.IAccessRequest = {
  subject: {
    id: 'user-1',
    roles: ['editor', 'viewer'],
    attributes: { department: 'engineering', level: 3 },
  },
  action: 'update',
  resource: {
    type: 'post',
    id: 'post-42',
    attributes: { ownerId: 'user-1', published: true },
  },
  scope: 'org-1',
  environment: { ip: '10.0.0.1', userAgent: 'test-agent' },
}

describe('iamResolve()', () => {
  it('resolves action shorthand', () => {
    expect(iamResolve(baseRequest, 'action')).toBe('update')
  })

  it('resolves scope shorthand', () => {
    expect(iamResolve(baseRequest, 'scope')).toBe('org-1')
  })

  it('resolves scope as null when missing', () => {
    const req = { ...baseRequest, scope: undefined }
    expect(iamResolve(req, 'scope')).toBeNull()
  })

  it('resolves subject.id', () => {
    expect(iamResolve(baseRequest, 'subject.id')).toBe('user-1')
  })

  it('resolves subject.roles', () => {
    expect(iamResolve(baseRequest, 'subject.roles')).toEqual(['editor', 'viewer'])
  })

  it('resolves subject.attributes.*', () => {
    expect(iamResolve(baseRequest, 'subject.attributes.department')).toBe('engineering')
    expect(iamResolve(baseRequest, 'subject.attributes.level')).toBe(3)
  })

  it('resolves resource.type', () => {
    expect(iamResolve(baseRequest, 'resource.type')).toBe('post')
  })

  it('resolves resource.id', () => {
    expect(iamResolve(baseRequest, 'resource.id')).toBe('post-42')
  })

  it('resolves resource.attributes.*', () => {
    expect(iamResolve(baseRequest, 'resource.attributes.ownerId')).toBe('user-1')
    expect(iamResolve(baseRequest, 'resource.attributes.published')).toBe(true)
  })

  it('resolves environment.*', () => {
    expect(iamResolve(baseRequest, 'environment.ip')).toBe('10.0.0.1')
  })

  it('returns null for missing paths', () => {
    expect(iamResolve(baseRequest, 'subject.attributes.missing')).toBeNull()
  })

  it('rejects paths with disallowed root prefix', () => {
    expect(iamResolve(baseRequest, 'nonexistent')).toBeNull()
    expect(iamResolve(baseRequest, 'deeply.nested.missing.path')).toBeNull()
    expect(iamResolve(baseRequest, 'toString')).toBeNull()
  })

  it('blocks __proto__ traversal', () => {
    expect(iamResolve(baseRequest, 'subject.__proto__')).toBeNull()
    expect(iamResolve(baseRequest, 'resource.__proto__.constructor')).toBeNull()
  })

  it('blocks constructor traversal', () => {
    expect(iamResolve(baseRequest, 'subject.constructor')).toBeNull()
    expect(iamResolve(baseRequest, 'resource.constructor.name')).toBeNull()
  })

  it('blocks prototype traversal', () => {
    expect(iamResolve(baseRequest, 'subject.prototype')).toBeNull()
  })
})

describe('iamMatchesAction()', () => {
  it('wildcard matches everything', () => {
    expect(iamMatchesAction('*', 'read')).toBe(true)
    expect(iamMatchesAction('*', 'anything')).toBe(true)
  })

  it('exact match', () => {
    expect(iamMatchesAction('read', 'read')).toBe(true)
    expect(iamMatchesAction('read', 'write')).toBe(false)
  })

  it('prefix wildcard: posts:* matches posts:read', () => {
    expect(iamMatchesAction('posts:*', 'posts:read')).toBe(true)
    expect(iamMatchesAction('posts:*', 'posts:write')).toBe(true)
    expect(iamMatchesAction('posts:*', 'users:read')).toBe(false)
  })

  it('non-wildcard does not match prefix', () => {
    expect(iamMatchesAction('posts', 'posts:read')).toBe(false)
  })
})

describe('iamMatchesResource()', () => {
  it('wildcard matches everything', () => {
    expect(iamMatchesResource('*', 'post')).toBe(true)
  })

  it('exact match', () => {
    expect(iamMatchesResource('post', 'post')).toBe(true)
    expect(iamMatchesResource('post', 'comment')).toBe(false)
  })

  it('prefix wildcard: org:* matches org:project', () => {
    expect(iamMatchesResource('org:*', 'org:project')).toBe(true)
    expect(iamMatchesResource('org:*', 'org:project:doc')).toBe(true)
    expect(iamMatchesResource('org:*', 'user')).toBe(false)
  })

  it('bare pattern does NOT match sub-resources', () => {
    // Breaking change vs prior behaviour: a bare "org" no longer implicitly
    // grants on "org:project". Authors must opt in with "org:*".
    expect(iamMatchesResource('org', 'org:project')).toBe(false)
    expect(iamMatchesResource('org', 'org:project:doc')).toBe(false)
    expect(iamMatchesResource('org', 'organization')).toBe(false)
  })

  it('bare pattern still matches the literal resource', () => {
    expect(iamMatchesResource('org', 'org')).toBe(true)
  })

  it('":*" suffix matches children', () => {
    expect(iamMatchesResource('org:*', 'org:billing')).toBe(true)
    expect(iamMatchesResource('org:*', 'org:project:doc')).toBe(true)
  })

  it('nested ":*" only matches under the named branch', () => {
    expect(iamMatchesResource('org:billing:*', 'org:billing:invoice')).toBe(true)
    expect(iamMatchesResource('org:billing:*', 'org:secrets:invoice')).toBe(false)
  })

  // `iamMatchesResource` is called directly by `policyApplies` /
  // `policyTargetsMatch`, so dot-pattern targets must match dot-style
  // request resources here. Colon-pattern behaviour is unchanged.
  it('dot wildcard: dashboard.* matches dot children', () => {
    expect(iamMatchesResource('dashboard.*', 'dashboard.users')).toBe(true)
    expect(iamMatchesResource('dashboard.*', 'dashboard.users.list')).toBe(true)
  })

  it('dot wildcard does NOT match bare literal nor sibling-prefix', () => {
    expect(iamMatchesResource('dashboard.*', 'dashboard')).toBe(false)
    expect(iamMatchesResource('dashboard.*', 'dashboard-x')).toBe(false)
  })

  it('colon wildcard still matches (regression check)', () => {
    expect(iamMatchesResource('org:billing:*', 'org:billing:invoice')).toBe(true)
    expect(iamMatchesResource('org:billing:*', 'org:billing')).toBe(false)
  })

  it('separator-mismatched prefixes do not cross-match', () => {
    // dot pattern must not match colon-separated resource (and vice versa).
    expect(iamMatchesResource('a.b.*', 'a:b:c')).toBe(false)
    expect(iamMatchesResource('a:b:*', 'a.b.c')).toBe(false)
  })
})

describe('iamMatchesResourceHierarchical()', () => {
  it('wildcard matches everything', () => {
    expect(iamMatchesResourceHierarchical('*', 'dashboard')).toBe(true)
  })

  it('exact match', () => {
    expect(iamMatchesResourceHierarchical('dashboard', 'dashboard')).toBe(true)
    expect(iamMatchesResourceHierarchical('dashboard', 'settings')).toBe(false)
  })

  it('dot wildcard: dashboard.* matches children', () => {
    expect(iamMatchesResourceHierarchical('dashboard.*', 'dashboard.users')).toBe(true)
    expect(iamMatchesResourceHierarchical('dashboard.*', 'dashboard.users.settings')).toBe(true)
    // does NOT match dashboard itself
    expect(iamMatchesResourceHierarchical('dashboard.*', 'dashboard')).toBe(false)
  })

  it('bare pattern does NOT match dot-children', () => {
    // Breaking change vs prior behaviour - bare "dashboard" only matches
    // the literal "dashboard". Authors must use "dashboard.*" for recursion.
    expect(iamMatchesResourceHierarchical('dashboard', 'dashboard.users')).toBe(false)
    expect(iamMatchesResourceHierarchical('dashboard', 'dashboard.users.settings')).toBe(false)
    expect(iamMatchesResourceHierarchical('dashboard', 'dashboards')).toBe(false)
  })

  it('nested ".*" only matches under the named branch', () => {
    expect(iamMatchesResourceHierarchical('dashboard.users.*', 'dashboard.users.settings')).toBe(true)
    expect(iamMatchesResourceHierarchical('dashboard.users.*', 'dashboard.admin.settings')).toBe(false)
  })
})

describe('iamMatchesScope()', () => {
  it('undefined/null pattern matches any scope', () => {
    expect(iamMatchesScope(undefined, 'org-1')).toBe(true)
    expect(iamMatchesScope(null, 'org-1')).toBe(true)
    expect(iamMatchesScope(undefined, undefined)).toBe(true)
  })

  it('wildcard matches any scope', () => {
    expect(iamMatchesScope('*', 'org-1')).toBe(true)
    expect(iamMatchesScope('*', undefined)).toBe(true)
  })

  it('specific pattern requires matching scope', () => {
    expect(iamMatchesScope('org-1', 'org-1')).toBe(true)
    expect(iamMatchesScope('org-1', 'org-2')).toBe(false)
  })

  it('specific pattern does not match missing scope', () => {
    expect(iamMatchesScope('org-1', undefined)).toBe(false)
    expect(iamMatchesScope('org-1', null)).toBe(false)
  })
})
