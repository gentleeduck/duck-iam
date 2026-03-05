// When your app data changes (user upgrades plan, org gets suspended, user gets flagged),
// you need to sync those changes to the duck-iam attributes table.
//
// Call these functions from your webhooks, cron jobs, or event handlers.

import { engine } from './access'
import { prisma } from './prisma'

/**
 * Sync a single user's attributes from your app tables to duck-iam.
 * Call this after: plan change, org change, flag change, etc.
 */
export async function syncUserAttributes(userId: string): Promise<void> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: { org: true },
  })

  if (!user) return

  await engine.admin.setAttributes(userId, {
    plan: user.plan,
    orgId: user.orgId,
    orgStatus: user.org?.status ?? 'unknown',
    email: user.email,
  })

  engine.invalidate()
}

/**
 * Sync all users in an org (e.g. when org status changes).
 */
export async function syncOrgAttributes(orgId: string): Promise<void> {
  const org = await prisma.org.findUnique({ where: { id: orgId } })
  if (!org) return

  const users = await prisma.user.findMany({
    where: { orgId },
    select: { id: true, plan: true },
  })

  for (const user of users) {
    await engine.admin.setAttributes(user.id, {
      plan: user.plan,
      orgId: org.id,
      orgStatus: org.status,
    })
  }

  engine.invalidate()
}

/**
 * Bulk sync all users. Run as a cron job (e.g. daily) to catch any drift.
 */
export async function syncAllAttributes(): Promise<void> {
  const users = await prisma.user.findMany({
    include: { org: true },
  })

  for (const user of users) {
    await engine.admin.setAttributes(user.id, {
      plan: user.plan,
      orgId: user.orgId,
      orgStatus: user.org?.status ?? 'unknown',
    })
  }

  engine.invalidate()
  console.log(`Synced attributes for ${users.length} users`)
}
