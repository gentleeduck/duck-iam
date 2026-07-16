import type { Identity, Session } from '@gentleduck/auth/core'
import { CurrentIdentity, CurrentSession, NestExceptionFilter } from '@gentleduck/auth/server/nestjs'
import { Controller, Get, UseFilters, UseGuards } from '@nestjs/common'
import { DuckAuthGuard } from '../auth/auth.guard'
import { Authorize } from '../iam/iam.decorators'
import { IamGuard } from '../iam/iam.guard'
import type { UsersService } from './users.service'

@Controller('users')
@UseGuards(DuckAuthGuard)
@UseFilters(NestExceptionFilter)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('me')
  me(
    @CurrentSession() session: Session.ISession,
    @CurrentIdentity() identity: Identity.IIdentity<{ email: string; name: string }>,
  ) {
    if (identity?.profile && session.identityId) {
      this.usersService.upsert(session.identityId, identity.profile)
    }

    return {
      ok: true as const,
      code: 'USERS_ME_OK' as const,
      data: session.identityId ? this.usersService.findById(session.identityId) : null,
    }
  }

  @Get()
  @UseGuards(IamGuard)
  @Authorize({ action: 'read', resource: 'user' })
  listAll() {
    return {
      ok: true as const,
      code: 'USERS_LIST_OK' as const,
      data: this.usersService.findAll(),
    }
  }
}
