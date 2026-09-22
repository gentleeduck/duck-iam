import { IamDrizzleAdapter } from '@gentleduck/iam/adapters/drizzle'
import { and, eq, isNull, or } from 'drizzle-orm'
import { buildAuth } from '../auth/auth.engine'
import { access, allRoles } from '../iam/iam.module'
import { db } from '.'
import { authAdapter } from './auth-adapter'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from './schema'

const auth = buildAuth()

const adapter = new IamDrizzleAdapter({
  db,
  json: 'string',
  ops: { and, eq, isNull, or },
  tables: { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles },
} as never)

const engine = access.createEngine({ adapter: adapter as never })

console.log('Syncing IAM roles...')
await engine.admin.import(
  { exportedAt: new Date().toISOString(), policies: [], roles: allRoles, schemaVersion: 1 },
  { mode: 'replace' },
)
console.log(`  synced ${allRoles.length} roles: ${allRoles.map((r) => r.id).join(', ')}`)

async function upsertUser(email: string, password: string, roleId: 'viewer' | 'editor' | 'admin') {
  const existing = await authAdapter.identities.find({ email })
  if (existing) {
    console.log(`  [skip] ${email} already exists`)
    await engine.admin.assignRole(existing.id, roleId)
    return existing.id
  }

  const name = email.split('@')[0] ?? email
  const identity = await auth.identities.create({ profile: { email, name, username: email } })
  await auth.passwords.set(identity.id, password, authAdapter.credentials)
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
