import type { AppAction, AppResource, AppRole, AppScope } from '@gentleduck/example-shared'
import { STANDARD_CHECKS } from '@gentleduck/example-shared'
import { Controller, Get, Inject, Req } from '@nestjs/common'
import type { Engine } from 'access-engine'
import { generatePermissionMap } from 'access-engine/server/generic'
import { ACCESS_ENGINE_TOKEN } from 'access-engine/server/nest'
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
