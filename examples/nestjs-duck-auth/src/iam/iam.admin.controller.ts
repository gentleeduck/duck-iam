import { NestExceptionFilter } from '@gentleduck/auth/server/nestjs'
import type { IamEngine } from '@gentleduck/iam'
import type { NestRequest } from '@gentleduck/iam/server/nest'
import { createIamAdminOperations, IAM_ACCESS_ENGINE_TOKEN } from '@gentleduck/iam/server/nest'
import {
  type ArgumentsHost,
  Body,
  Catch,
  Controller,
  Delete,
  type ExceptionFilter,
  Get,
  HttpException,
  Inject,
  Param,
  Post,
  Put,
  Req,
  UseFilters,
  UseGuards,
} from '@nestjs/common'
import type { Response } from 'express'
import { DuckAuthGuard } from '../auth/auth.guard'
import type { AppAction, AppResource, AppRole } from './iam.module'

type Engine = IamEngine<AppAction, AppResource, AppRole>
type AdminOps = ReturnType<typeof createIamAdminOperations<AppAction, AppResource, AppRole>>

@Catch(Error)
class AdminErrorFilter implements ExceptionFilter {
  catch(err: Error & { status?: number }, host: ArgumentsHost): void {
    if (err instanceof HttpException) throw err
    const res = host.switchToHttp().getResponse<Response>()
    const status = err.status ?? 500
    res.status(status).json({ ok: false, error: { status, message: err.message } })
  }
}

@UseGuards(DuckAuthGuard)
@UseFilters(NestExceptionFilter, AdminErrorFilter)
@Controller('iam/admin')
export class IamAdminController {
  private readonly h: AdminOps

  constructor(@Inject(IAM_ACCESS_ENGINE_TOKEN) engine: Engine) {
    this.h = createIamAdminOperations(engine, {
      authorize: async (req) => {
        const userId = req.session?.identityId
        if (!userId) return false
        return engine.can(userId, 'read', { type: 'settings', attributes: {} })
      },
    })
  }

  @Get('roles')
  listRoles(@Req() req: NestRequest) {
    return this.h.listRoles(req)
  }

  @Get('policies')
  listPolicies(@Req() req: NestRequest) {
    return this.h.listPolicies(req)
  }

  @Put('roles')
  saveRole(@Req() req: NestRequest, @Body() body: Parameters<AdminOps['saveRole']>[1]) {
    return this.h.saveRole(req, body)
  }

  @Put('policies')
  savePolicy(@Req() req: NestRequest, @Body() body: Parameters<AdminOps['savePolicy']>[1]) {
    return this.h.savePolicy(req, body)
  }

  @Post('subjects/:subjectId/roles')
  assignRole(
    @Req() req: NestRequest,
    @Param('subjectId') subjectId: string,
    @Body() body: Parameters<AdminOps['assignRole']>[2],
  ) {
    return this.h.assignRole(req, subjectId, body)
  }

  @Delete('subjects/:subjectId/roles/:roleId')
  revokeRole(@Req() req: NestRequest, @Param('subjectId') subjectId: string, @Param('roleId') roleId: AppRole) {
    return this.h.revokeRole(req, subjectId, roleId)
  }
}
