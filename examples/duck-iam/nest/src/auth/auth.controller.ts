import type { AppAuth } from '@examples/duck-iam-shared/auth'
import { DUCK_AUTH_TOKEN, type NestAdapter, nestSession, nestSignIn, nestSignOut } from '@gentleduck/auth/server/nestjs'
import { Controller, Get, Inject, Post, Req, Res } from '@nestjs/common'

/** duck-auth's own handlers, which guard their CSRF themselves. */
@Controller('auth')
export class AuthController {
  constructor(@Inject(DUCK_AUTH_TOKEN) private readonly auth: AppAuth) {}

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
}
