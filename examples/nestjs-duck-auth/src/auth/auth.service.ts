import type { AuthEngine } from '@gentleduck/auth'
import { rethrowAuthError, throwAuthError } from '@gentleduck/auth'
import type { Identity } from '@gentleduck/auth/core'
import { parseSignInBody } from '@gentleduck/auth/server/generic'
import { DUCK_AUTH_TOKEN } from '@gentleduck/auth/server/nestjs'
import type { IamEngine } from '@gentleduck/iam'
import { IAM_ACCESS_ENGINE_TOKEN } from '@gentleduck/iam/server/nest'
import { Inject, Injectable } from '@nestjs/common'
import type { SignUpDto } from './dto/sign-in.dto'

@Injectable()
export class AuthService {
  constructor(
    @Inject(DUCK_AUTH_TOKEN) private readonly auth: AuthEngine,
    @Inject(IAM_ACCESS_ENGINE_TOKEN) private readonly iam: IamEngine,
  ) {}

  async signUp(dto: SignUpDto): Promise<{ ok: true; code: 'AUTH_SIGNUP_SUCCEEDED'; data: { id: string } }> {
    try {
      const identity = await this.auth.identities.create({
        profile: { email: dto.email, name: dto.name },
      })
      await this.auth.passwords.set(identity.id, dto.password)
      await this.iam.admin.assignRole(identity.id, 'viewer')
      return { ok: true, code: 'AUTH_SIGNUP_SUCCEEDED', data: { id: identity.id } }
    } catch (error) {
      rethrowAuthError(error, 'AUTH_MISCONFIGURED', { detail: 'signup failed' })
    }
  }

  parseSignIn(body: unknown) {
    const parsed = parseSignInBody(body)
    if (!parsed) throwAuthError('AUTH_INVALID_CREDENTIALS')
    return parsed
  }

  async resolveIdentity(id: string): Promise<Identity.IIdentity<unknown>> {
    try {
      const identity = await this.auth.identities.getById(id)
      if (!identity) throwAuthError('AUTH_UNAUTHENTICATED')
      return identity
    } catch (error) {
      rethrowAuthError(error, 'AUTH_UNAUTHENTICATED')
    }
  }
}
