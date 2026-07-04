import { AuthEngine } from '@gentleduck/auth'
import { authCreateSqlStores } from '@gentleduck/auth/adapters/sql'
import { AuthCookieTransport } from '@gentleduck/auth/core/transport'
import { authPassword } from '@gentleduck/auth/providers/password'
import { IamDrizzleAdapter } from '@gentleduck/iam/adapters/drizzle'
import { and, eq } from 'drizzle-orm'
import { access, allRoles } from '../iam/iam.module'
import { db } from '.'
import { createAuthDrizzleBunSqliteBridge } from './auth-bridge'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from './schema'

const bridge = createAuthDrizzleBunSqliteBridge(db as never)
const stores = authCreateSqlStores(bridge)

const auth = new AuthEngine({
  baseUrl: 'http://localhost:3001',
  transport: new AuthCookieTransport({ name: 'duck-sid', secure: false }),
  stores,
})

auth.providers.register(
  authPassword({
    findIdentityByEmail: (email) => stores.identities.findByEmail(email, {}),
    passwords: auth.passwords,
  }),
)

const adapter = new IamDrizzleAdapter({
  db,
  tables: { policies: iamPolicies, roles: iamRoles, assignments: iamAssignments, attrs: iamSubjectAttrs },
  ops: { eq, and },
  json: 'string',
} as never)

const engine = access.createEngine({ adapter: adapter as never })

console.log('Syncing IAM roles...')
await engine.admin.import(
  { schemaVersion: 1, exportedAt: new Date().toISOString(), roles: allRoles, policies: [] },
  { mode: 'replace' },
)
console.log(`  synced ${allRoles.length} roles: ${allRoles.map((r) => r.id).join(', ')}`)

async function upsertUser(email: string, password: string, roleId: 'viewer' | 'editor' | 'admin') {
  const existing = await stores.identities.findByEmail(email, {})
  if (existing) {
    console.log(`  [skip] ${email} already exists`)
    await engine.admin.assignRole(existing.id, roleId)
    return existing.id
  }
  const identity = await auth.identities.create({ profile: { email, name: email.split('@')[0] } })
  await auth.passwords.set(identity.id, password)
  await engine.admin.assignRole(identity.id, roleId)
  console.log(`  [created] ${email} -> role: ${roleId}`)
  return identity.id
}

console.log('\nSeeding demo users...')
await upsertUser('viewer@example.com', 'password123', 'viewer')
await upsertUser('editor@example.com', 'password123', 'editor')
await upsertUser('admin@example.com', 'password123', 'admin')

console.log('\nDone. Sign in with:')
console.log('  viewer@example.com / password123')
console.log('  editor@example.com / password123')
console.log('  admin@example.com  / password123')
