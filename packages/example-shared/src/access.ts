import { createAccessConfig } from 'duck-iam'
import { PrismaAdapter } from 'duck-iam/adapters/prisma'
import { prisma } from './prisma'

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 1. Create typed config (actions + resources + scopes are const literals)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export const access = createAccessConfig({
  scopes: ['system', 'tenant'],
  actions: ['create', 'read', 'update', 'delete', 'publish', 'manage', 'export', 'access'],
  resources: [
    'post',
    'comment',
    'user',
    'org',
    'analytics',
    'billing',
    'settings',
    'role',
    'profile',
    // Hierarchical resources: granting 'dashboard' also grants 'dashboard.users', etc.
    'dashboard',
    'dashboard.users',
    'dashboard.users.settings',
    'dashboard.billing',
  ],
})

/** Union of all valid actions */
export type AppAction = (typeof access.actions)[number]

/** Union of all valid resources */
export type AppResource = (typeof access.resources)[number]

/** Union of all valid scopes */
export type AppScope = (typeof access.scopes)[number]

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 2. Define roles (type-checked actions + resources + scopes)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const roles = {
  viewer: access
    .defineRole('viewer')
    .name('Viewer')
    .desc('Read-only access to public resources')
    .grantRead('post', 'comment', 'profile')
    .build(),

  author: access
    .defineRole('author')
    .name('Author')
    .desc('Can create and manage own content')
    .inherits('viewer')
    .grant('create', 'post')
    .grant('create', 'comment')
    // Authors can only update/delete their own posts
    .grantWhen('update', 'post', (w) => w.isOwner())
    .grantWhen('delete', 'post', (w) => w.isOwner())
    .build(),

  editor: access
    .defineRole('editor')
    .name('Editor')
    .desc('Can manage all content')
    .inherits('author')
    .grant('update', 'post') // any post, not just own
    .grant('delete', 'post')
    .grant('update', 'comment')
    .grant('delete', 'comment')
    .grant('publish', 'post')
    .grant('read', 'dashboard')
    .build(),

  admin: access
    .defineRole('admin')
    .name('Admin')
    .desc('Full access to everything')
    .inherits('editor')
    .grantAll('user')
    .grantAll('org')
    .grantAll('settings')
    .grantAll('billing')
    .grantAll('role')
    .grantAll('dashboard')
    .grantAll('dashboard.users')
    .grantAll('dashboard.billing')
    .build(),

  superadmin: access
    .defineRole('superadmin')
    .name('Super Admin')
    .desc('God mode')
    .inherits('admin')
    .grantAll('*')
    .build(),

  // Scoped roles: restrict to specific scopes
  tenantAdmin: access
    .defineRole('tenant-admin')
    .name('Tenant Admin')
    .desc('Admin within a tenant scope')
    .scope('tenant')
    .grantAll('user')
    .grantAll('settings')
    .grantAll('billing')
    .grantAll('dashboard')
    .grantAll('dashboard.users')
    .grantAll('dashboard.users.settings')
    .grantAll('dashboard.billing')
    .build(),

  systemAdmin: access
    .defineRole('system-admin')
    .name('System Admin')
    .desc('System-level admin')
    .scope('system')
    .grantAll('*')
    .build(),
}

/** Union of all role IDs: 'viewer' | 'author' | 'editor' | ... */
export type AppRole = (typeof roles)[keyof typeof roles]['id']

export { roles }

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 3. Define ABAC policies (cross-cutting concerns)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export const policies = {
  security: access
    .policy('security')
    .name('Security Policies')
    .algorithm('deny-overrides')

    // Suspended orgs are blocked from everything
    .rule('suspended-org', (r) =>
      r
        .deny()
        .on('*')
        .of('*')
        .priority(100)
        .desc('Block suspended orgs')
        .when((w) => w.attr('orgStatus', 'eq', 'suspended')),
    )

    // Rate limiting (checked via environment)
    .rule('rate-limit-writes', (r) =>
      r
        .deny()
        .on('create', 'update', 'delete')
        .of('*')
        .priority(90)
        .desc('Rate limit write operations')
        .when((w) => w.env('requestsPerMinute', 'gt', 60)),
    )

    .build(),

  planGating: access
    .policy('plan-gating')
    .name('Plan-Based Feature Gating')
    .algorithm('deny-overrides')

    // Only pro+ can access analytics
    .rule('analytics-pro-only', (r) =>
      r
        .allow()
        .on('read')
        .of('analytics')
        .when((w) => w.attr('plan', 'in', ['pro', 'enterprise'])),
    )

    // Only enterprise can manage org settings
    .rule('org-settings-enterprise', (r) =>
      r
        .allow()
        .on('update', 'delete')
        .of('org')
        .when((w) => w.attr('plan', 'eq', 'enterprise')),
    )

    // Only enterprise can export data
    .rule('export-enterprise', (r) =>
      r
        .allow()
        .on('export')
        .of('*')
        .when((w) => w.attr('plan', 'eq', 'enterprise')),
    )

    // System-scope dashboard access requires system admin
    .rule('system-dashboard', (r) =>
      r
        .allow()
        .on('read', 'manage')
        .of('dashboard', 'dashboard.users', 'dashboard.users.settings', 'dashboard.billing')
        .forScope('system')
        .when((w) => w.roles('system-admin', 'superadmin')),
    )

    .build(),

  contentModeration: access
    .policy('content-moderation')
    .name('Content Moderation Rules')
    .algorithm('deny-overrides')

    // Flagged users can't create content
    .rule('flagged-no-create', (r) =>
      r
        .deny()
        .on('create')
        .of('post', 'comment')
        .priority(80)
        .desc('Flagged users cannot create content')
        .when((w) => w.attr('flagged', 'eq', true)),
    )

    // Unpublished posts only visible to author and editors
    .rule('unpublished-visibility', (r) =>
      r
        .deny()
        .on('read')
        .of('post')
        .priority(50)
        .desc('Unpublished posts are restricted')
        .when((w) =>
          w
            .resourceAttr('published', 'eq', false)
            .not((n) => n.or((o) => o.isOwner().role('editor').role('admin').role('superadmin'))),
        ),
    )

    .build(),
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 4. Create engine instance
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export const engine = access.createEngine({
  adapter: new PrismaAdapter(prisma as any),
  defaultEffect: 'deny',
  cacheTTL: 30, // 30s cache for policies/roles
  maxCacheSize: 500, // cache up to 500 resolved subjects

  hooks: {
    onDeny: (req, decision) => {
      console.warn(
        `[duck-iam] DENIED: subject=${req.subject.id} ` +
          `action=${req.action} resource=${req.resource.type}` +
          `${req.resource.id ? `:${req.resource.id}` : ''} ` +
          `${req.scope ? `scope=${req.scope} ` : ''}` +
          `reason="${decision.reason}" (${decision.duration.toFixed(2)}ms)`,
      )
    },
    onError: (error, req) => {
      console.error(`[duck-iam] ERROR evaluating ${req.action}:${req.resource.type}`, error)
    },
  },
})

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 5. Permission check definitions for the frontend
//    Centralize these so server + client agree on the keys.
//    Typos like { action: 'craete' } are caught at compile time.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export const STANDARD_CHECKS = access.checks([
  { action: 'create', resource: 'post' },
  { action: 'read', resource: 'post' },
  { action: 'publish', resource: 'post' },
  { action: 'manage', resource: 'user' },
  { action: 'read', resource: 'analytics' },
  { action: 'update', resource: 'org' },
  { action: 'access', resource: 'billing' },
  { action: 'export', resource: 'post' },
  { action: 'manage', resource: 'role' },
  { action: 'read', resource: 'dashboard' },
  // Scoped checks
  { action: 'manage', resource: 'dashboard.users', scope: 'tenant' },
  { action: 'manage', resource: 'settings', scope: 'system' },
])
