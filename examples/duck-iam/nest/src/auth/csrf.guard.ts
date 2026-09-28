import type { AppAuth } from '@examples/duck-iam-shared/auth'
import { DUCK_AUTH_TOKEN, makeCsrfGuard } from '@gentleduck/auth/server/nestjs'
import { type CanActivate, type ExecutionContext, Inject, Injectable } from '@nestjs/common'

/** duck-auth's CSRF guard as an injectable, for this app's own controllers. */
@Injectable()
export class CsrfGuard implements CanActivate {
  private readonly guard

  constructor(@Inject(DUCK_AUTH_TOKEN) auth: AppAuth) {
    this.guard = makeCsrfGuard(auth)
  }

  canActivate(ctx: ExecutionContext): Promise<boolean> {
    return this.guard.canActivate(ctx)
  }
}
