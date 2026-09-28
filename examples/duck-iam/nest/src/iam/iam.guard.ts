import type { IamEngine } from '@gentleduck/iam'
import { IAM_ACCESS_ENGINE_TOKEN, iamNestAccessGuard } from '@gentleduck/iam/server/nest'
import { type CanActivate, type ExecutionContext, Inject, Injectable } from '@nestjs/common'
import { sessionOf } from '../session/session'
import type { AppAction, AppResource, AppScope } from './iam.module'

@Injectable()
export class IamGuard implements CanActivate {
  private readonly check: (ctx: ExecutionContext) => Promise<boolean>

  constructor(@Inject(IAM_ACCESS_ENGINE_TOKEN) engine: IamEngine<AppAction, AppResource, string, AppScope>) {
    this.check = iamNestAccessGuard(engine, {
      getUserId: (req) => sessionOf(req)?.id ?? null,
      getScope: (req) => sessionOf(req)?.companyId ?? undefined,
      // One shared guard instance for every route; harmless for non-`users` resources since only
      // `deny-self-account-delete` reads `resource.attributes.id`.
      getResourceAttributes: (req) => ({ id: req.params?.id ?? '' }),
    })
  }

  canActivate(ctx: ExecutionContext): Promise<boolean> {
    return this.check(ctx)
  }
}
