import type { IamEngine } from '@gentleduck/iam'
import { IAM_ACCESS_ENGINE_TOKEN } from '@gentleduck/iam/server/nest'
import { Controller, Get, Inject, Res } from '@nestjs/common'
import type { Response } from 'express'
import type { AppAction, AppResource, AppScope } from '../iam/iam.module'

// Unauthenticated on purpose: a load balancer or uptime probe hits this before it has a session.
@Controller()
export class HealthController {
  constructor(
    @Inject(IAM_ACCESS_ENGINE_TOKEN) private readonly engine: IamEngine<AppAction, AppResource, string, AppScope>,
  ) {}

  @Get('health')
  async health(@Res({ passthrough: true }) res: Response) {
    const health = await this.engine.healthCheck()
    res.status(health.ok ? 200 : 503)
    return health
  }
}
