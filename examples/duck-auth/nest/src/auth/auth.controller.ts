import type { AppAuth } from '@examples/duck-auth-shared/auth'
import { beginProvider, currentSession, providerCallback, signIn, signOut } from '@examples/duck-auth-shared/routes'
import { applyIntents, type ExpressAdapter } from '@gentleduck/auth/server/express'
import { nodeHeadersToFetch } from '@gentleduck/auth/server/generic'
import { DUCK_AUTH_TOKEN, type NestAdapter, nestCaller } from '@gentleduck/auth/server/nestjs'
import { All, Body, Controller, Get, Inject, Param, Post, Req, Res, UseGuards } from '@nestjs/common'
import { CsrfGuard } from './csrf.guard'

/** Sign-in, sign-out, the session and the provider routes. Nest runs on Express here, so Express's intents
 *  writer applies. */
@Controller('auth')
export class AuthController {
  constructor(@Inject(DUCK_AUTH_TOKEN) private readonly auth: AppAuth) {}

  @Get('providers')
  providers() {
    return { providers: this.auth.providers.list() }
  }

  @Post('signin')
  @UseGuards(CsrfGuard)
  async signIn(@Req() req: NestAdapter.Request, @Body() body: unknown, @Res() res: ExpressAdapter.Response) {
    applyIntents(await signIn(this.auth, nodeHeadersToFetch(req.headers), body, nestCaller(req)), res)
  }

  @Post('signout')
  @UseGuards(CsrfGuard)
  async signOut(@Req() req: NestAdapter.Request, @Res() res: ExpressAdapter.Response) {
    applyIntents(await signOut(this.auth, nodeHeadersToFetch(req.headers)), res)
  }

  @Get('session')
  async session(@Req() req: NestAdapter.Request, @Res() res: ExpressAdapter.Response) {
    const body = await currentSession(this.auth, nodeHeadersToFetch(req.headers))
    applyIntents([{ type: 'json', status: 200, body }], res)
  }

  @Post('providers/:id/begin')
  @UseGuards(CsrfGuard)
  async begin(@Param('id') id: string, @Body() body: unknown, @Res() res: ExpressAdapter.Response) {
    applyIntents(await beginProvider(this.auth, id, body), res)
  }

  /** Where the IdP returns the browser; never guarded. Apple's form post is parsed as text in `main.ts`, the
   *  same query string a redirect carries. */
  @All('providers/:id/callback')
  async callback(
    @Param('id') id: string,
    @Req() req: NestAdapter.Request & { url: string },
    @Body() form: unknown,
    @Res() res: ExpressAdapter.Response,
  ) {
    const params =
      req.method === 'POST'
        ? new URLSearchParams(typeof form === 'string' ? form : '')
        : new URL(req.url, 'http://localhost').searchParams
    applyIntents(await providerCallback(this.auth, id, params, nodeHeadersToFetch(req.headers), nestCaller(req)), res)
  }
}
