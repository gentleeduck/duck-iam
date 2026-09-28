import { type AppAuth, PAGES } from '@examples/duck-auth-shared/auth'
import { signedIn } from '@examples/duck-auth-shared/session'
import { nodeHeadersToFetch } from '@gentleduck/auth/server/generic'
import { DUCK_AUTH_TOKEN, type NestAdapter } from '@gentleduck/auth/server/nestjs'
import { Controller, Get, Header, HttpCode, Inject, Post, Req, UseGuards } from '@nestjs/common'
import { CsrfGuard } from '../auth/csrf.guard'

@Controller('me')
@UseGuards(CsrfGuard)
export class MeController {
  constructor(@Inject(DUCK_AUTH_TOKEN) private readonly auth: AppAuth) {}

  @Get()
  @Header('cache-control', 'no-store')
  async me(@Req() req: NestAdapter.Request) {
    const { identity, session, totp } = await signedIn(this.auth, nodeHeadersToFetch(req.headers))
    return { identity, totp, session: { id: session.id, aal: session.aal, expiresAt: session.expiresAt } }
  }

  @Post('email/resend')
  @HttpCode(200)
  async resend(@Req() req: NestAdapter.Request) {
    const { identity } = await signedIn(this.auth, nodeHeadersToFetch(req.headers))
    return this.auth.flows.requestEmailVerification({ identityId: identity.id, callbackPath: PAGES.verifyEmail })
  }

  @Get('sessions')
  @Header('cache-control', 'no-store')
  async sessions(@Req() req: NestAdapter.Request) {
    const { identity } = await signedIn(this.auth, nodeHeadersToFetch(req.headers))
    return { sessions: await this.auth.sessions.listForIdentity(identity.id) }
  }

  @Post('sessions/revoke-others')
  @HttpCode(200)
  async revokeOthers(@Req() req: NestAdapter.Request) {
    const headers = nodeHeadersToFetch(req.headers)
    const { identity } = await signedIn(this.auth, headers)
    return this.auth.sessions.revokeAllExcept(identity.id, this.auth.transport.extract({ headers }) ?? '')
  }
}
