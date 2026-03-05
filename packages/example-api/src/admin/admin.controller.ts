import type { AppAction, AppResource, AppRole, AppScope } from '@gentleduck/example-shared'
import { prisma, syncOrgAttributes, syncUserAttributes } from '@gentleduck/example-shared'
import { Controller, Get, Inject, Param, Post } from '@nestjs/common'
import type { Engine } from 'duck-iam'
import { ACCESS_ENGINE_TOKEN } from 'duck-iam/server/nest'
import { Authorize } from '../access/authorize'

@Controller('admin')
export class AdminController {
  constructor(
    @Inject(ACCESS_ENGINE_TOKEN)
    private readonly engine: Engine<AppAction, AppResource, AppRole, AppScope>,
  ) {}

  // ── User management (requires manage:user) ──

  @Get('users')
  @Authorize({ action: 'manage', resource: 'user' })
  async listUsers() {
    return prisma.user.findMany({ include: { org: true } })
  }

  // ── Analytics (pro+ only, enforced by plan-gating policy) ──

  @Get('analytics')
  @Authorize({ action: 'read', resource: 'analytics' })
  async getAnalytics() {
    return { views: 12345, posts: 42 }
  }

  // ── Scoped dashboard access ──
  // Only tenant-admin or admin+ can access dashboard.users in tenant scope

  @Get('dashboard/users')
  @Authorize({ action: 'read', resource: 'dashboard.users', scope: 'tenant' })
  async getDashboardUsers() {
    return prisma.user.findMany({ select: { id: true, name: true, email: true, plan: true } })
  }

  // Only system-admin can access dashboard.users.settings in system scope

  @Get('dashboard/users/settings')
  @Authorize({ action: 'manage', resource: 'dashboard.users.settings', scope: 'system' })
  async getDashboardSettings() {
    return { settings: { maxUsers: 100, allowSignups: true } }
  }

  // ── Attribute sync (admin action) ──

  @Post('sync-attributes/:userId')
  @Authorize({ action: 'manage', resource: 'user' })
  async syncAttributes(@Param('userId') userId: string) {
    await syncUserAttributes(userId)
    this.engine.invalidate()
    return { synced: true }
  }

  @Post('sync-org/:orgId')
  @Authorize({ action: 'manage', resource: 'org' })
  async syncOrg(@Param('orgId') orgId: string) {
    await syncOrgAttributes(orgId)
    this.engine.invalidate()
    return { synced: true }
  }
}
