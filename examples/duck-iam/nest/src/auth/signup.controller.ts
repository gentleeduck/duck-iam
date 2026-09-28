import type { AppAuth } from '@examples/duck-iam-shared/auth'
import { signUp } from '@examples/duck-iam-shared/signup'
import { DUCK_AUTH_TOKEN } from '@gentleduck/auth/server/nestjs'
import type { IamEngine } from '@gentleduck/iam'
import { IAM_ACCESS_ENGINE_TOKEN } from '@gentleduck/iam/server/nest'
import { Body, Controller, Inject, Post, UseGuards } from '@nestjs/common'
import { db } from '../db'
import type { AppAction, AppResource, AppScope } from '../iam/iam.module'
import { CsrfGuard } from './csrf.guard'

/** This app's own sign-up route — CSRF-guarded, unlike `AuthController`'s duck-auth-owned handlers. */
@Controller('auth')
@UseGuards(CsrfGuard)
export class SignupController {
  constructor(
    @Inject(DUCK_AUTH_TOKEN) private readonly auth: AppAuth,
    @Inject(IAM_ACCESS_ENGINE_TOKEN) private readonly engine: IamEngine<AppAction, AppResource, string, AppScope>,
  ) {}

  @Post('signup')
  async signUp(@Body() body: unknown) {
    return signUp(this.auth, db, (id, companyId) => this.engine.admin.assignRole(id, 'admin', companyId), body)
  }
}
