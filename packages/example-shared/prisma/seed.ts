// Seeds the access-engine tables with roles, policies, and test data.
//
// Run with: bun prisma/seed.ts
// Or: npx prisma db seed

import { PrismaClient } from '@prisma/client'
import { policies, roles } from '../src/access'

const prisma = new PrismaClient()

async function main() {
  console.log('Seeding access-engine tables...\n')

  // ── 1. Seed roles ──

  const allRoles = Object.values(roles)
  for (const role of allRoles) {
    await prisma.accessRole.upsert({
      where: { id: role.id },
      create: {
        id: role.id,
        name: role.name,
        description: role.description ?? null,
        permissions: role.permissions as any,
        inherits: (role.inherits as string[]) ?? [],
        scope: role.scope ?? null,
        metadata: (role.metadata ?? null) as any,
      },
      update: {
        name: role.name,
        description: role.description ?? null,
        permissions: role.permissions as any,
        inherits: (role.inherits as string[]) ?? [],
        scope: role.scope ?? null,
      },
    })
    console.log(`  ✓ Role: ${role.id} (${role.name})${role.scope ? ` [scope: ${role.scope}]` : ''}`)
  }

  // ── 2. Seed policies ──

  const allPolicies = Object.values(policies)
  for (const pol of allPolicies) {
    await prisma.accessPolicy.upsert({
      where: { id: pol.id },
      create: {
        id: pol.id,
        name: pol.name,
        description: pol.description ?? null,
        version: pol.version ?? 1,
        algorithm: pol.algorithm,
        rules: pol.rules as any,
        targets: (pol.targets ?? null) as any,
      },
      update: {
        name: pol.name,
        description: pol.description ?? null,
        version: pol.version ?? 1,
        algorithm: pol.algorithm,
        rules: pol.rules as any,
        targets: (pol.targets ?? null) as any,
      },
    })
    console.log(`  ✓ Policy: ${pol.id} (${pol.name})`)
  }

  // ── 3. Seed test users ──

  const testOrg = await prisma.org.upsert({
    where: { id: 'org-acme' },
    create: { id: 'org-acme', name: 'Acme Corp', status: 'active' },
    update: {},
  })

  const testUsers = [
    { id: 'user-alice', email: 'alice@acme.com', name: 'Alice', plan: 'enterprise', orgId: testOrg.id, role: 'admin' },
    { id: 'user-bob', email: 'bob@acme.com', name: 'Bob', plan: 'pro', orgId: testOrg.id, role: 'editor' },
    { id: 'user-carol', email: 'carol@acme.com', name: 'Carol', plan: 'pro', orgId: testOrg.id, role: 'author' },
    { id: 'user-dave', email: 'dave@acme.com', name: 'Dave', plan: 'free', orgId: testOrg.id, role: 'viewer' },
  ]

  for (const u of testUsers) {
    await prisma.user.upsert({
      where: { id: u.id },
      create: { id: u.id, email: u.email, name: u.name, plan: u.plan, orgId: u.orgId },
      update: { plan: u.plan },
    })

    await prisma.accessAssignment.upsert({
      where: {
        subjectId_roleId_scope: {
          subjectId: u.id,
          roleId: u.role,
          scope: '',
        },
      },
      create: { subjectId: u.id, roleId: u.role, scope: '' },
      update: {},
    })

    await prisma.accessSubjectAttr.upsert({
      where: { subjectId: u.id },
      create: {
        subjectId: u.id,
        data: {
          plan: u.plan,
          orgId: u.orgId,
          orgStatus: testOrg.status,
          flagged: false,
        },
      },
      update: {
        data: {
          plan: u.plan,
          orgId: u.orgId,
          orgStatus: testOrg.status,
          flagged: false,
        },
      },
    })

    console.log(`  ✓ User: ${u.id} (${u.name}) → role: ${u.role}, plan: ${u.plan}`)
  }

  // Create test posts
  await prisma.post.upsert({
    where: { id: 'post-1' },
    create: { id: 'post-1', title: 'Hello World', body: 'My first post', published: true, authorId: 'user-carol' },
    update: {},
  })

  await prisma.post.upsert({
    where: { id: 'post-2' },
    create: { id: 'post-2', title: 'Draft Post', body: 'Work in progress', published: false, authorId: 'user-carol' },
    update: {},
  })

  console.log('\nSeed complete.\n')
  console.log('Test credentials:')
  console.log('  alice (admin/enterprise) - full access')
  console.log('  bob   (editor/pro)       - content management, analytics')
  console.log('  carol (author/pro)       - own content only, analytics')
  console.log('  dave  (viewer/free)      - read only, no analytics')
}

main()
  .catch((e) => {
    console.error(e)
    process.exit(1)
  })
  .finally(() => prisma.$disconnect())
