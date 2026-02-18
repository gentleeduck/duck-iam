import type { AppAction, AppResource, AppRole, AppScope } from '@gentleduck/example-shared'
import { type CanActivate, type ExecutionContext, Inject, Injectable } from '@nestjs/common'
import type { Engine } from 'access-engine'
import { ACCESS_ENGINE_TOKEN, nestAccessGuard } from 'access-engine/server/nest'

@Injectable()
export class AccessGuard implements CanActivate {
  private readonly check: (context: ExecutionContext) => Promise<boolean>

  constructor(
    @Inject(ACCESS_ENGINE_TOKEN)
    engine: Engine<AppAction, AppResource, AppRole, AppScope>,
  ) {
    this.check = nestAccessGuard(engine, {
      getUserId: (req) => {
        const auth = req.headers?.authorization
        if (typeof auth === 'string' && auth.startsWith('Bearer ')) return auth.slice(7)
        return (req.user?.id as string | undefined) ?? null
      },
    })
  }

  canActivate(context: ExecutionContext): Promise<boolean> {
    return this.check(context)
  }
}
