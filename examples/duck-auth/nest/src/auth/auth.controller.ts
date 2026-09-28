import { type AppAuth, landing } from '@examples/duck-auth-shared/auth'
import { applyIntents, type ExpressAdapter } from '@gentleduck/auth/server/express'
import { oauthCallback } from '@gentleduck/auth/server/generic'
import {
  DUCK_AUTH_TOKEN,
  type NestAdapter,
  nestCaller,
  nestProviderBegin,
  nestSession,
  nestSignIn,
  nestSignOut,
} from '@gentleduck/auth/server/nestjs'
import { All, Controller, Get, Inject, Post, Req, Res } from '@nestjs/common'

/** duck-auth's own handlers, which guard their CSRF themselves. */
@Controller('auth')
export class AuthController {
  constructor(@Inject(DUCK_AUTH_TOKEN) private readonly auth: AppAuth) {}

  @Get('providers')
  providers() {
    return { providers: this.auth.providers.list() }
  }

  @Post('signin')
  signIn(@Req() req: NestAdapter.Request, @Res() res: NestAdapter.Response) {
    return nestSignIn(this.auth)(req, res)
  }

  @Post('signout')
  signOut(@Req() req: NestAdapter.Request, @Res() res: NestAdapter.Response) {
    return nestSignOut(this.auth)(req, res)
  }

  @Get('session')
  session(@Req() req: NestAdapter.Request, @Res() res: NestAdapter.Response) {
    return nestSession(this.auth)(req, res)
  }

  @Post('providers/:id/begin')
  begin(@Req() req: NestAdapter.Request, @Res() res: NestAdapter.Response) {
    return nestProviderBegin(this.auth)(req, res)
  }

  /** Where the IdP returns the browser; the cookies land, then the app takes over. Nest runs on Express
   *  here, so Express's intents writer applies. */
  @All('providers/:id/callback')
  async callback(@Req() req: NestAdapter.Request, @Res() res: ExpressAdapter.Response) {
    const request = { body: req.body, cookie: req.headers.cookie, method: req.method, url: req.url ?? '' }
    const intents = await landing(oauthCallback(this.auth, req.params?.id, request, nestCaller(req)))
    applyIntents(intents, res)
  }
}
