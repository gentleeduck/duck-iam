import type { IamEngine } from '@gentleduck/iam'
import { IAM_ACCESS_ENGINE_TOKEN } from '@gentleduck/iam/server/nest'
import { Controller, Get, Inject, Req } from '@nestjs/common'
import type { Request } from 'express'
import { ANONYMOUS_SUBJECT_ID, type AppAction, type AppResource, type AppScope, access } from '../iam/iam.module'
import { sessionOf } from '../session/session'

// One engine.permissions() call over the full action x resource matrix, so this can't drift
// from what the route guards actually enforce.
@Controller()
export class PermissionsController {
  constructor(
    @Inject(IAM_ACCESS_ENGINE_TOKEN) private readonly engine: IamEngine<AppAction, AppResource, string, AppScope>,
  ) {}

  @Get('me/permissions')
  async myPermissions(@Req() req: Request) {
    const session = sessionOf(req) ?? { id: ANONYMOUS_SUBJECT_ID, companyId: null }
    const scope = session.companyId ?? undefined
    const checks = access.resources.flatMap((resource) => access.actions.map((action) => ({ action, resource, scope })))
    const map = await this.engine.permissions(session.id, checks)
    return { subject: session.id, scope: scope ?? null, permissions: map }
  }
}
