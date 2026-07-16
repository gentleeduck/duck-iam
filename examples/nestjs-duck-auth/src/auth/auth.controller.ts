import type { AuthEngine } from '@gentleduck/auth'
import type { Identity, Session } from '@gentleduck/auth/core'
import type { NestAdapter } from '@gentleduck/auth/server/nestjs'
import {
  CurrentIdentity,
  CurrentSession,
  DUCK_AUTH_TOKEN,
  NestExceptionFilter,
  nestProviderBegin,
  nestSession,
  nestSignIn,
  nestSignOut,
} from '@gentleduck/auth/server/nestjs'
import { Body, Controller, Get, Inject, Post, Req, Res, UseFilters, UseGuards } from '@nestjs/common'
import { DuckAuthGuard } from './auth.guard'
import type { AuthService } from './auth.service'
import type { SignUpDto } from './dto/sign-in.dto'

@Controller('auth')
@UseFilters(NestExceptionFilter)
export class AuthController {
  constructor(
    @Inject(DUCK_AUTH_TOKEN) private readonly auth: AuthEngine,
    private readonly authService: AuthService,
  ) {}

  @Post('signup')
  signUp(@Body() body: SignUpDto) {
    return this.authService.signUp(body)
  }

  @Post('signin')
  signIn(@Req() req: NestAdapter.Request, @Res() res: NestAdapter.Reply) {
    return nestSignIn(this.auth)(req, res)
  }

  @Post('signout')
  signOut(@Req() req: NestAdapter.Request, @Res() res: NestAdapter.Reply) {
    return nestSignOut(this.auth)(req, res)
  }

  @Get('session')
  session(@Req() req: NestAdapter.Request, @Res() res: NestAdapter.Reply) {
    return nestSession(this.auth)(req, res)
  }

  @Post('providers/:id/begin')
  providerBegin(@Req() req: NestAdapter.Request, @Res() res: NestAdapter.Reply) {
    return nestProviderBegin(this.auth)(req, res)
  }

  @Get('me')
  @UseGuards(DuckAuthGuard)
  me(@CurrentSession() session: Session.ISession, @CurrentIdentity() identity: Identity.IIdentity<unknown>) {
    return {
      ok: true as const,
      code: 'AUTH_ME_OK' as const,
      data: { session, identity },
    }
  }
}
