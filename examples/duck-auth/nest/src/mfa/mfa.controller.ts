import type { AppAuth } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { signedIn, stepUp } from '@examples/duck-auth-shared/session'
import { AuthError } from '@gentleduck/auth/core'
import { applyIntents, type ExpressAdapter } from '@gentleduck/auth/server/express'
import { nodeHeadersToFetch } from '@gentleduck/auth/server/generic'
import { DUCK_AUTH_TOKEN, type NestAdapter, nestCaller } from '@gentleduck/auth/server/nestjs'
import { Body, Controller, HttpCode, Inject, Post, Req, Res, UseGuards } from '@nestjs/common'
import { CsrfGuard } from '../auth/csrf.guard'

@Controller('auth/mfa')
@UseGuards(CsrfGuard)
export class MfaController {
  constructor(@Inject(DUCK_AUTH_TOKEN) private readonly auth: AppAuth) {}

  @Post('verify')
  async verify(@Req() req: NestAdapter.Request, @Res() res: ExpressAdapter.Response) {
    applyIntents(await stepUp(this.auth, nodeHeadersToFetch(req.headers), req.body, nestCaller(req)), res)
  }

  @Post('totp/begin')
  @HttpCode(200)
  async beginTotp(@Req() req: NestAdapter.Request) {
    const { identity } = await signedIn(this.auth, nodeHeadersToFetch(req.headers))
    return this.auth.mfa.beginTotpEnrollment(identity.id, identity.profile.email)
  }

  @Post('totp/confirm')
  @HttpCode(200)
  async confirmTotp(@Req() req: NestAdapter.Request, @Body() body: unknown) {
    const { identity } = await signedIn(this.auth, nodeHeadersToFetch(req.headers))
    const confirmed = await this.auth.mfa.confirmTotpEnrollment(identity.id, readString(body, 'code') ?? '')
    if (!confirmed.ok) throw new AuthError('AUTH_INVALID_CREDENTIALS')
    return { backupCodes: confirmed.backupCodes }
  }

  @Post('totp/remove')
  @HttpCode(200)
  async removeTotp(@Req() req: NestAdapter.Request) {
    const { identity } = await signedIn(this.auth, nodeHeadersToFetch(req.headers))
    await this.auth.mfa.removeTotp(identity.id)
    await this.auth.mfa.removeBackupCodes(identity.id)
    return { ok: true }
  }

  @Post('backup-codes')
  @HttpCode(200)
  async backupCodes(@Req() req: NestAdapter.Request) {
    const { identity } = await signedIn(this.auth, nodeHeadersToFetch(req.headers))
    return { backupCodes: await this.auth.mfa.regenerateBackupCodes(identity.id) }
  }
}
