import { type AppAuth, PAGES } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { signUp } from '@examples/duck-auth-shared/signup'
import { applyIntents, type ExpressAdapter } from '@gentleduck/auth/server/express'
import { nodeHeadersToFetch } from '@gentleduck/auth/server/generic'
import { DUCK_AUTH_TOKEN, type NestAdapter } from '@gentleduck/auth/server/nestjs'
import { Body, Controller, HttpCode, Inject, Post, Req, Res, UseGuards } from '@nestjs/common'
import { CsrfGuard } from './csrf.guard'

/** This app's own sign-up and recovery routes. */
@Controller('auth')
@UseGuards(CsrfGuard)
export class RecoveryController {
  constructor(@Inject(DUCK_AUTH_TOKEN) private readonly auth: AppAuth) {}

  @Post('signup')
  signUp(@Body() body: unknown) {
    return signUp(this.auth, body)
  }

  @Post('password/forgot')
  @HttpCode(200)
  async forgot(@Body() body: unknown) {
    await this.auth.flows.requestPasswordReset({
      input: { email: readString(body, 'email') ?? '', callbackPath: PAGES.resetPassword },
      findIdentityByEmail: (e) => this.auth.identities.getByEmail(e).orNull(),
    })
    return { ok: true }
  }

  @Post('password/reset')
  async reset(@Req() req: NestAdapter.Request, @Body() body: unknown, @Res() res: ExpressAdapter.Response) {
    const { intents } = await this.auth.flows.completePasswordReset({
      token: readString(body, 'token') ?? '',
      newPassword: readString(body, 'password') ?? '',
      currentSid: this.auth.transport.extract({ headers: nodeHeadersToFetch(req.headers) }) ?? undefined,
    })
    applyIntents([...intents, { type: 'json', status: 200, body: { ok: true } }], res)
  }

  @Post('email/verify')
  @HttpCode(200)
  async verifyEmail(@Body() body: unknown) {
    const { identityId } = await this.auth.flows.completeEmailVerification({ token: readString(body, 'token') ?? '' })
    return { identityId }
  }
}
