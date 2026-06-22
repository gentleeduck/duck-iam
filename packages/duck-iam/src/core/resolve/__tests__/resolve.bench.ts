import { bench, describe } from 'vitest'
import type { IamRequest } from '../../types'
import { iamMatchesAction, iamMatchesResource, iamMatchesResourceHierarchical, iamResolve } from '../resolve'

const req: IamRequest.IAccessRequest = {
  subject: { id: 'u1', roles: ['editor'], attributes: { status: 'active', level: 3 } },
  action: 'read',
  resource: { type: 'post', id: 'post-42', attributes: { ownerId: 'u1', published: true } },
  environment: { ip: '10.0.0.1', timestamp: Date.now() },
}

describe('iamResolve', () => {
  bench('shorthand (action)', () => {
    iamResolve(req, 'action')
  })

  bench('one level (subject.id)', () => {
    iamResolve(req, 'subject.id')
  })

  bench('two levels (subject.attributes.status)', () => {
    iamResolve(req, 'subject.attributes.status')
  })

  bench('three levels (resource.attributes.ownerId)', () => {
    iamResolve(req, 'resource.attributes.ownerId')
  })

  bench('cache miss then hit (alternates)', () => {
    // Path cache should hit for repeat lookups.
    iamResolve(req, 'subject.attributes.status')
    iamResolve(req, 'resource.attributes.ownerId')
  })
})

describe('iamMatchesAction', () => {
  bench('exact match', () => {
    iamMatchesAction('read', 'read')
  })

  bench('star wildcard', () => {
    iamMatchesAction('*', 'read')
  })

  bench('colon-prefix wildcard', () => {
    iamMatchesAction('posts:*', 'posts:read')
  })

  bench('no match', () => {
    iamMatchesAction('read', 'write')
  })
})

describe('iamMatchesResource', () => {
  bench('exact', () => {
    iamMatchesResource('post', 'post')
  })

  bench('parent-prefix (org -> org:project)', () => {
    iamMatchesResource('org', 'org:project')
  })

  bench('colon-wildcard', () => {
    iamMatchesResource('org:*', 'org:project')
  })
})

describe('iamMatchesResourceHierarchical', () => {
  bench('exact', () => {
    iamMatchesResourceHierarchical('dashboard', 'dashboard')
  })

  bench('parent-prefix (dashboard -> dashboard.users)', () => {
    iamMatchesResourceHierarchical('dashboard', 'dashboard.users')
  })

  bench('dot-wildcard', () => {
    iamMatchesResourceHierarchical('dashboard.*', 'dashboard.users')
  })
})
