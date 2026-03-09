import { defineRole, Engine, MemoryAdapter } from '@gentleduck/iam'

// --------------------------------------------------------------------------------

type Roles = 'viewer' | 'editor' | 'admin' | 'commenter' | 'moderator'
type Subjects = 'comment' | 'post' | 'user' | 'dashboard'
type Permissions = 'create' | 'read' | 'update' | 'delete' | 'list' | 'manage'
type Scopes = 'public' | 'private'

const f = (name: Roles) => defineRole<Roles, Permissions, Subjects, Scopes>(name)

export const viewer = f('viewer').grant('read', 'post').grant('read', 'comment').build()

const editor = f('editor')
  .inherits('viewer')
  .grant('create', 'post')
  .grant('update', 'post')
  .grant('create', 'comment')
  .grant('update', 'comment')
  .build()

const admin = f('admin')
  .inherits('editor')
  .grant('delete', 'post')
  .grant('delete', 'comment')
  .grant('manage', 'user')
  .grant('manage', 'dashboard')
  .build()

const commenter = f('commenter').grant('create', 'comment').grant('update', 'comment').build()

const moderator = f('moderator').inherits('viewer', 'commenter').grant('delete', 'comment').build()

// --------------------------------------------------------------------------------

const adapter = new MemoryAdapter({
  roles: [viewer, editor, admin, commenter, moderator],
  assignments: {
    alice: ['viewer'],
    bob: ['editor'],
    charlie: ['admin'],
  },
})

const engine = new Engine({
  adapter,
})

async function main() {
  // Viewer: can read, cannot create
  console.log('alice read post:', await engine.can('alice', 'read', { type: 'post', attributes: {} }))
  // true
  console.log('alice create post:', await engine.can('alice', 'create', { type: 'post', attributes: {} }))
  // false

  // Editor: can read (inherited) + create
  console.log('bob read post:', await engine.can('bob', 'read', { type: 'post', attributes: {} }))
  // true
  console.log('bob create post:', await engine.can('bob', 'create', { type: 'post', attributes: {} }))
  // true
  console.log('bob delete post:', await engine.can('bob', 'delete', { type: 'post', attributes: {} }))
  // false

  // Admin: can do everything
  console.log('charlie delete post:', await engine.can('charlie', 'delete', { type: 'post', attributes: {} }))
  // true
  console.log('charlie manage user:', await engine.can('charlie', 'manage', { type: 'user', attributes: {} }))
  // true
}

main()
