import { buildAuth } from './auth'
import { type AppDb, type AppRole, allPolicies, allRoles, buildEngine } from './iam'
import { companies, orders, products, users } from './schema'

/** Every seeded account shares this password, so the README's curl/UI walkthroughs stay one line. */
export const DEMO_PASSWORD = 'duckiam-examples'

// Identity ids are real duck-auth uuids now, generated on first seed — not deterministic, so
// idempotency keys off email (like duck-auth's own seed) rather than a hardcoded id.
export async function seedDb(db: AppDb) {
  const engine = buildEngine(db)
  const auth = buildAuth(db)

  console.log('Syncing IAM roles + policies...')
  await engine.admin.import(
    { exportedAt: new Date().toISOString(), policies: allPolicies, roles: allRoles, schemaVersion: 1 },
    { mode: 'replace' },
  )
  console.log(`  synced ${allRoles.length} roles, ${allPolicies.length} policies`)

  async function upsertCompany(id: string, name: string) {
    await db.insert(companies).values({ id, name }).onConflictDoNothing()
  }

  async function upsertUser(email: string, name: string, companyId: string, roleId: AppRole): Promise<string> {
    const existing = await auth.identities.getByEmail(email).orNull()
    const identity =
      existing ?? (await auth.identities.create({ emailVerified: true, profile: { email, name, username: email } }))
    await auth.passwords.set(identity.id, DEMO_PASSWORD, auth.cfg.stores.credentials)
    await db.insert(users).values({ id: identity.id, email, name, companyId }).onConflictDoNothing()
    await engine.admin.assignRole(identity.id, roleId, companyId)
    console.log(`  [seeded] ${email} -> ${roleId}@${companyId}`)
    return identity.id
  }

  console.log('\nSeeding companies...')
  await upsertCompany('company-acme', 'Acme Co')
  await upsertCompany('company-globex', 'Globex Inc')

  console.log('\nSeeding users...')
  await upsertUser('viewer@acme.test', 'Acme Viewer', 'company-acme', 'viewer')
  const staffAcmeId = await upsertUser('staff@acme.test', 'Acme Staff', 'company-acme', 'staff')
  await upsertUser('manager@acme.test', 'Acme Manager', 'company-acme', 'manager')
  await upsertUser('admin@acme.test', 'Acme Admin', 'company-acme', 'admin')
  const viewerGlobexId = await upsertUser('viewer@globex.test', 'Globex Viewer', 'company-globex', 'viewer')

  console.log('\nSeeding products + orders...')
  await db
    .insert(products)
    .values({
      id: 'product-widget-acme',
      companyId: 'company-acme',
      ownerId: staffAcmeId,
      name: 'Acme Widget',
      priceCents: 2500,
    })
    .onConflictDoNothing()

  await db
    .insert(orders)
    .values({
      id: 'order-1-acme',
      companyId: 'company-acme',
      ownerId: staffAcmeId,
      productId: 'product-widget-acme',
      quantity: 3,
      status: 'pending',
    })
    .onConflictDoNothing()

  await db
    .insert(products)
    .values({
      id: 'product-widget-globex',
      companyId: 'company-globex',
      ownerId: viewerGlobexId,
      name: 'Globex Widget',
      priceCents: 4200,
    })
    .onConflictDoNothing()

  console.log(`\nDone. Sign in with email + password "${DEMO_PASSWORD}" using:`)
  console.log('  viewer@acme.test / staff@acme.test / manager@acme.test / admin@acme.test  (company-acme)')
  console.log('  viewer@globex.test  (company-globex, cannot see company-acme rows)')
}
