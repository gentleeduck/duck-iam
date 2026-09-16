import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { createIam } from '../../config/config'
import { IamEngine } from '../../engine'

// Sections 2 and 4 of `guides/duck-iam-setup.md` verbatim, so the guide's ABAC examples cannot drift from the real API.
interface AppContext {
  environment: { region: string; hour: number }
  resourceAttributes: {
    comment: { ownerId: string }
    post: { ownerId: string; status: 'draft' | 'ready' | 'published' }
  }
  subject: { attributes: { orgId: string; tier: 'free' | 'pro' }; id: string; roles: string[] }
}

const iam = createIam({
  actions: ['create', 'read', 'update', 'delete', 'publish', 'archive'] as const,
  context: {} as unknown as AppContext,
  resources: ['post', 'comment', 'user', 'org', 'invoice'] as const,
  roles: ['viewer', 'editor', 'admin', 'billing'] as const,
  scopes: ['org:acme', 'org:beta'] as const,
})

const postOwnerPolicy = iam
  .definePolicy('post-owner')
  .name('Post owner or admin may update')
  .algorithm('deny-overrides')
  .rule('owner-or-admin', (r) =>
    r
      .allow()
      .on('update')
      .of('post')
      .when((w) => w.or((o) => o.isOwner().role('admin'))),
  )
  .build()

const publishGatePolicy = iam
  .definePolicy('publish-gate')
  .name('Publish only what is ready')
  .rule('ready-editors-only', (r) =>
    r
      .allow()
      .on('publish')
      .of('post')
      .when((w) => w.resourceAttr('status', 'eq', 'ready').role('editor')),
  )
  .build()

const orgScopePolicy = iam
  .definePolicy('org-scope')
  .name('Editors act only inside their own org')
  .rule('own-org-only', (r) =>
    r
      .allow()
      .on('create', 'update')
      .of('post')
      .forScope('org:acme')
      .when((w) => w.role('editor').attr('orgId', 'eq', 'acme')),
  )
  .build()

type Action = 'create' | 'read' | 'update' | 'delete' | 'publish' | 'archive'
type ResourceType = 'post' | 'comment' | 'user' | 'org' | 'invoice'
type RoleId = 'viewer' | 'editor' | 'admin' | 'billing'
type Scope = 'org:acme' | 'org:beta'

function makeEngine(policies: Array<typeof postOwnerPolicy>) {
  return new IamEngine<Action, ResourceType, RoleId, Scope>({
    adapter: new IamMemoryAdapter<Action, ResourceType, RoleId, Scope>({
      assignments: { u1: ['editor'], u2: ['editor'], u3: ['admin'] },
      attributes: { u1: { orgId: 'acme' }, u2: { orgId: 'beta' }, u3: { orgId: 'acme' } },
      policies,
      roles: [
        { id: 'editor', name: 'Editor', permissions: [] },
        { id: 'admin', name: 'Admin', permissions: [] },
      ],
    }),
    cacheTTL: 0,
  })
}

describe('guide §4: post-owner policy', () => {
  const engine = makeEngine([postOwnerPolicy])

  it('lets the owner update their own post', async () => {
    expect(await engine.can('u1', 'update', { attributes: { ownerId: 'u1' }, type: 'post' })).toBe(true)
  })

  it('lets an admin update anyone else’s post', async () => {
    expect(await engine.can('u3', 'update', { attributes: { ownerId: 'u1' }, type: 'post' })).toBe(true)
  })

  it('denies a non-owner without the admin role', async () => {
    expect(await engine.can('u2', 'update', { attributes: { ownerId: 'u1' }, type: 'post' })).toBe(false)
  })
})

describe('guide §4: publish-gate policy', () => {
  const engine = makeEngine([publishGatePolicy])

  it('lets an editor publish a ready post', async () => {
    expect(await engine.can('u1', 'publish', { attributes: { status: 'ready' }, type: 'post' })).toBe(true)
  })

  it('denies publishing a draft', async () => {
    expect(await engine.can('u1', 'publish', { attributes: { status: 'draft' }, type: 'post' })).toBe(false)
  })

  it('denies a non-editor even on a ready post', async () => {
    expect(await engine.can('u3', 'publish', { attributes: { status: 'ready' }, type: 'post' })).toBe(false)
  })
})

describe('guide §4: org-scope policy', () => {
  const engine = makeEngine([orgScopePolicy])

  it('lets an editor in the right org create in the right scope', async () => {
    expect(await engine.can('u1', 'create', { attributes: {}, type: 'post' }, undefined, 'org:acme')).toBe(true)
  })

  it('denies an editor whose org attribute does not match', async () => {
    expect(await engine.can('u2', 'create', { attributes: {}, type: 'post' }, undefined, 'org:acme')).toBe(false)
  })

  it('denies the same editor outside the rule’s scope', async () => {
    expect(await engine.can('u1', 'create', { attributes: {}, type: 'post' }, undefined, 'org:beta')).toBe(false)
  })
})
