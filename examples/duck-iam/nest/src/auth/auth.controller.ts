import type { AppAuth } from '@examples/duck-iam-shared/auth'
import { currentSession, signIn, signOut } from '@examples/duck-iam-shared/routes'
import { applyIntents, type ExpressAdapter } from '@gentleduck/auth/server/express'
import { nodeHeadersToFetch } from '@gentleduck/auth/server/generic'
import { DUCK_AUTH_TOKEN, type NestAdapter, nestCaller } from '@gentleduck/auth/server/nestjs'
import { Body, Controller, Get, Inject, Post, Req, Res, UseGuards } from '@nestjs/common'
import { CsrfGuard } from './csrf.guard'

/** Sign-in, sign-out and the session. Nest runs on Express here, so Express's intents writer applies. */
@Controller('auth')
@UseGuards(CsrfGuard)
export class AuthController {
  constructor(@Inject(DUCK_AUTH_TOKEN) private readonly auth: AppAuth) {}

  @Post('signin')
  async signIn(@Req() req: NestAdapter.Request, @Body() body: unknown, @Res() res: ExpressAdapter.Response) {
    applyIntents(await signIn(this.auth, nodeHeadersToFetch(req.headers), body, nestCaller(req)), res)
  }

  @Post('signout')
  async signOut(@Req() req: NestAdapter.Request, @Res() res: ExpressAdapter.Response) {
    applyIntents(await signOut(this.auth, nodeHeadersToFetch(req.headers)), res)
  }

  @Get('session')
  async session(@Req() req: NestAdapter.Request, @Res() res: ExpressAdapter.Response) {
    const body = await currentSession(this.auth, nodeHeadersToFetch(req.headers))
    applyIntents([{ type: 'json', status: 200, body }], res)
  }
}
