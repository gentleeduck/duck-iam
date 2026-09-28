import { buildAuth } from '@examples/duck-auth-shared/auth'
import { DUCK_AUTH_TOKEN, NestExceptionFilter } from '@gentleduck/auth/server/nestjs'
import { Global, Module } from '@nestjs/common'
import { APP_FILTER } from '@nestjs/core'
import { db } from '../db'
import { AuthController } from './auth.controller'
import { CsrfGuard } from './csrf.guard'
import { RecoveryController } from './recovery.controller'

@Global()
@Module({
  controllers: [AuthController, RecoveryController],
  providers: [
    { provide: DUCK_AUTH_TOKEN, useFactory: () => buildAuth(db) },
    // An AuthError keeps its code and status; Nest answers everything else itself.
    { provide: APP_FILTER, useClass: NestExceptionFilter },
    CsrfGuard,
  ],
  exports: [DUCK_AUTH_TOKEN, CsrfGuard],
})
export class AuthModule {}
