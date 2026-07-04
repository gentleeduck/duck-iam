import type { AuthEngine } from '@gentleduck/auth'
import { DUCK_AUTH_TOKEN, makeGuard } from '@gentleduck/auth/server/nestjs'
import { type CanActivate, type ExecutionContext, Inject, Injectable } from '@nestjs/common'

@Injectable()
export class DuckAuthGuard implements CanActivate {
  private readonly check: (ctx: ExecutionContext) => Promise<boolean>

  constructor(@Inject(DUCK_AUTH_TOKEN) auth: AuthEngine) {
    this.check = makeGuard(auth).canActivate
  }

  canActivate(ctx: ExecutionContext): Promise<boolean> {
    return this.check(ctx)
  }
}
