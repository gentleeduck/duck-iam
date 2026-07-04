import type { IamEngine } from '@gentleduck/iam'
import { IAM_ACCESS_ENGINE_TOKEN, iamNestAccessGuard } from '@gentleduck/iam/server/nest'
import { type CanActivate, type ExecutionContext, Inject, Injectable } from '@nestjs/common'
import type { AppAction, AppResource } from './iam.module'

@Injectable()
export class IamGuard implements CanActivate {
  private readonly check: (ctx: ExecutionContext) => Promise<boolean>

  constructor(@Inject(IAM_ACCESS_ENGINE_TOKEN) engine: IamEngine<AppAction, AppResource>) {
    this.check = iamNestAccessGuard(engine, {
      getUserId: (req) => (req as { session?: { identityId?: string } }).session?.identityId ?? null,
    })
  }

  canActivate(ctx: ExecutionContext): Promise<boolean> {
    return this.check(ctx)
  }
}
