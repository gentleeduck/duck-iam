import 'reflect-metadata'
import { DUCK_AUTH_TOKEN } from '@gentleduck/auth/server/nestjs'
import { Global, Module, type Provider } from '@nestjs/common'
import { AuthController } from './auth.controller'
import { buildAuth } from './auth.engine'
import { DuckAuthGuard } from './auth.guard'
import { AuthService } from './auth.service'

export { DUCK_AUTH_TOKEN }

const engineProvider: Provider = {
  provide: DUCK_AUTH_TOKEN,
  useFactory: buildAuth,
}

@Global()
@Module({
  controllers: [AuthController],
  exports: [DUCK_AUTH_TOKEN, AuthService, DuckAuthGuard],
  providers: [engineProvider, AuthService, DuckAuthGuard],
})
export class AuthModule {}
