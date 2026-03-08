import { defineRole, Engine, MemoryAdapter, PolicyBuilder } from '@gentleduck/iam'

// --------------------------------------------------------------------------------

type Roles = 'viewer' | 'admin'
type Subjects = 'comment' | 'post'
type Permissions = 'read' | 'write'
type Scopes = 'public' | 'private'

const f = (name: Roles) => defineRole<Roles, Permissions, Subjects, Scopes>(name)

const viewer = f('viewer')
  .name('viewer')
  .desc('This is the viewer role')
  .grant('read', 'comment')
  .grant('read', 'post')
  .meta({
    public: false,
  })
  .build()

const admin = f('admin')
  .name('admin')
  .desc('This is the admin role')
  .grant('read', 'comment')
  .grant('read', 'post')
  .grant('write', 'comment')
  .grant('write', 'post')
  .build()

// --------------------------------------------------------------------------------

const adapter = new MemoryAdapter({
  roles: [viewer],
  assignments: {
    alice: ['viewer'],
  },
})

const engine = new Engine({
  adapter,
})

const yes_can = await engine.can('alice', 'read', {
  id: 'comment:1',
  type: 'comment',
  attributes: {
    public: true,
  },
})

const no_can_not = await engine.check(
  'alice',
  'write',
  {
    id: 'comment:1',
    type: 'comment',
    attributes: {
      public: true,
    },
  },
  {
    id: 'post:1',
    type: 'post',
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
  },
  'public',
)

console.log(`alice can read comment:1, attributes: ${yes_can}`)
console.log(`alice can not write comment:1, attributes: ${JSON.stringify(no_can_not, null, 2)}`)
