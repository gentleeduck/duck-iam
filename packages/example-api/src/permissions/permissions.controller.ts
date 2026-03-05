import type { AppAction, AppResource, AppRole, AppScope } from '@gentleduck/example-shared'
import { STANDARD_CHECKS } from '@gentleduck/example-shared'
import { Controller, Get, Inject, Req } from '@nestjs/common'
import type { Engine } from 'duck-iam'
import { generatePermissionMap } from 'duck-iam/server/generic'
import { ACCESS_ENGINE_TOKEN } from 'duck-iam/server/nest'
import { type AuthenticatedRequest, extractUserId } from '../shared/auth'

@Controller('me')
export class PermissionsController {
  constructor(
    @Inject(ACCESS_ENGINE_TOKEN)
    private readonly engine: Engine<AppAction, AppResource, AppRole, AppScope>,
  ) {}

  @Get('permissions')
  async getPermissions(@Req() req: AuthenticatedRequest) {
    const userId = extractUserId(req)
    return generatePermissionMap(this.engine, userId, STANDARD_CHECKS)
  }
}
