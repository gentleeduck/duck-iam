import { readString } from '@examples/duck-iam-shared/body'
import { userOwnsRows } from '@examples/duck-iam-shared/deletion-guards'
import { isAppRole, setRole } from '@examples/duck-iam-shared/iam'
import { users } from '@examples/duck-iam-shared/schema'
import type { IamEngine } from '@gentleduck/iam'
import { IAM_ACCESS_ENGINE_TOKEN } from '@gentleduck/iam/server/nest'
import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  Delete,
  Get,
  HttpCode,
  Inject,
  NotFoundException,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common'
import { and, eq } from 'drizzle-orm'
import type { Request } from 'express'
import { CsrfGuard } from '../auth/csrf.guard'
import { db } from '../db'
import { Authorize } from '../iam/iam.decorators'
import { IamGuard } from '../iam/iam.guard'
import { type AppAction, type AppResource, type AppScope, access } from '../iam/iam.module'
import { sessionOf } from '../session/session'

@Controller('users')
@UseGuards(CsrfGuard, IamGuard)
export class UsersController {
  constructor(
    @Inject(IAM_ACCESS_ENGINE_TOKEN) private readonly engine: IamEngine<AppAction, AppResource, string, AppScope>,
  ) {}

  @Get()
  @Authorize({ action: 'read', resource: 'users' })
  async list(@Req() req: Request) {
    const companyId = sessionOf(req)?.companyId
    return companyId ? db.select().from(users).where(eq(users.companyId, companyId)) : []
  }

  // Same tenant-filter reasoning as companies.controller.ts.
  @Get(':id')
  @Authorize({ action: 'read', resource: 'users' })
  async getOne(@Req() req: Request, @Param('id') id: string) {
    const companyId = sessionOf(req)?.companyId
    if (!companyId) throw new NotFoundException({ error: 'not found' })
    const [row] = await db
      .select()
      .from(users)
      .where(and(eq(users.id, id), eq(users.companyId, companyId)))
      .limit(1)
    if (!row) throw new NotFoundException({ error: 'not found' })
    return row
  }

  // `deny-self-account-delete` blocks this when the target row is the caller's own.
  @Delete(':id')
  @Authorize({ action: 'delete', resource: 'users' })
  async remove(@Req() req: Request, @Param('id') id: string) {
    const companyId = sessionOf(req)?.companyId
    if (!companyId) throw new NotFoundException({ error: 'not found' })
    // Same FK-violation reasoning as companies.controller.ts: check before the DB refuses it the hard way.
    if (await userOwnsRows(db, id)) {
      throw new ConflictException({ error: 'cannot delete a user who owns products or orders' })
    }
    const deleted = await db
      .delete(users)
      .where(and(eq(users.id, id), eq(users.companyId, companyId)))
      .returning({ id: users.id })
    if (deleted.length === 0) throw new NotFoundException({ error: 'not found' })
    return { ok: true }
  }

  @Post(':id/role')
  @HttpCode(200)
  @Authorize({ action: 'manageRoles', resource: 'users' })
  async assignRole(@Req() req: Request, @Param('id') targetId: string, @Body() body: unknown) {
    const roleId = readString(body, 'roleId')
    const scope = sessionOf(req)?.companyId
    if (!isAppRole(roleId)) throw new BadRequestException({ error: `roleId must be one of ${access.roles.join(', ')}` })
    if (!scope) throw new BadRequestException({ error: 'caller has no company scope' })
    const [target] = await db
      .select({ id: users.id })
      .from(users)
      .where(and(eq(users.id, targetId), eq(users.companyId, scope)))
      .limit(1)
    if (!target) throw new NotFoundException({ error: 'not found' })
    await setRole(this.engine, db, targetId, roleId, scope)
    return { ok: true, userId: targetId, roleId, scope }
  }
}
