import type { AuthEngine } from '@gentleduck/auth'
import type { Identities, Sessions } from '@gentleduck/auth/core'
import { applyIntents, type ExpressAdapter } from '@gentleduck/auth/server/express'
import { nodeHeadersToFetch } from '@gentleduck/auth/server/generic'
import {
  CurrentIdentity,
  CurrentSession,
  DUCK_AUTH_TOKEN,
  type NestAdapter,
  NestExceptionFilter,
  nestCaller,
} from '@gentleduck/auth/server/nestjs'
import { Body, Controller, Get, Inject, Post, Req, Res, UseFilters, UseGuards } from '@nestjs/common'
import { CsrfGuard, DuckAuthGuard } from './auth.guard'
import type { AuthService } from './auth.service'
import type { SignUpDto } from './dto/sign-in.dto'

/** Sign-up, sign-in, sign-out and the session over `auth.flows`. Nest runs on Express here, so Express's intents
 *  writer applies. */
@Controller('auth')
@UseFilters(NestExceptionFilter)
@UseGuards(CsrfGuard)
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
  async signIn(@Req() req: NestAdapter.Request, @Body() body: unknown, @Res() res: ExpressAdapter.Response) {
    const { providerId, input } = this.authService.parseSignIn(body)
    const headers = nodeHeadersToFetch(req.headers)
    const { intents } = await this.auth.flows.signIn({
      input,
      providerId,
      ...nestCaller(req),
      previousSid: this.auth.transport.extract({ headers }) ?? undefined,
    })
    applyIntents(intents, res)
  }

  @Post('signout')
  async signOut(@Req() req: NestAdapter.Request, @Res() res: ExpressAdapter.Response) {
    const sid = this.auth.transport.extract({ headers: nodeHeadersToFetch(req.headers) })
    applyIntents(sid ? (await this.auth.flows.signOut(sid)).intents : this.auth.transport.revoke(), res)
  }

  @Get('session')
  async session(@Req() req: NestAdapter.Request, @Res() res: ExpressAdapter.Response) {
    const resolved = await this.auth.resolveSession({ headers: nodeHeadersToFetch(req.headers) }).orNull()
    if (!resolved) return applyIntents([{ type: 'json', status: 200, body: { session: null, identity: null } }], res)
    // `csrfHash` is server-side state; the browser holds the plaintext.
    const { csrfHash: _csrfHash, ...session } = resolved.session
    applyIntents([{ type: 'json', status: 200, body: { session, identity: resolved.identity } }], res)
  }

  @Get('me')
  @UseGuards(DuckAuthGuard)
  me(@CurrentSession() session: Sessions.Me, @CurrentIdentity() identity: Identities.Me) {
    return {
      ok: true as const,
      code: 'AUTH_ME_OK' as const,
      data: { session, identity },
    }
  }
}
