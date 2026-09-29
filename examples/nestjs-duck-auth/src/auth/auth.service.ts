import type { AuthEngine } from '@gentleduck/auth'
import { rethrowAuthError, throwAuthError } from '@gentleduck/auth'
import type { Identities } from '@gentleduck/auth/core'
import { DUCK_AUTH_TOKEN } from '@gentleduck/auth/server/nestjs'
import type { IamEngine } from '@gentleduck/iam'
import { IAM_ACCESS_ENGINE_TOKEN } from '@gentleduck/iam/server/nest'
import { Inject, Injectable } from '@nestjs/common'
import { authAdapter } from '../db/auth-adapter'
import type { UserProfile } from './auth.profile'
import type { SignInDto, SignUpDto } from './dto/sign-in.dto'

@Injectable()
export class AuthService {
  constructor(
    @Inject(DUCK_AUTH_TOKEN) private readonly auth: AuthEngine<UserProfile>,
    @Inject(IAM_ACCESS_ENGINE_TOKEN) private readonly iam: IamEngine,
  ) {}

  async signUp(dto: SignUpDto): Promise<{ ok: true; code: 'AUTH_SIGNUP_SUCCEEDED'; data: { id: string } }> {
    try {
      const identity = await this.auth.identities.create({
        profile: { email: dto.email, name: dto.name, username: dto.email },
      })
      await this.auth.passwords.set(identity.id, dto.password, authAdapter.credentials)
      await this.iam.admin.assignRole(identity.id, 'viewer')
      return { ok: true, code: 'AUTH_SIGNUP_SUCCEEDED', data: { id: identity.id } }
    } catch (error) {
      rethrowAuthError(error, 'AUTH_MISCONFIGURED', { detail: 'signup failed' })
    }
  }

  parseSignIn(body: unknown): SignInDto {
    if (typeof body !== 'object' || body === null) throwAuthError('AUTH_INVALID_PARAMETERS')
    const providerId: unknown = Reflect.get(body, 'providerId')
    if (typeof providerId !== 'string' || !providerId) throwAuthError('AUTH_INVALID_PARAMETERS')
    return { input: Reflect.get(body, 'input') ?? {}, providerId }
  }

  async resolveIdentity(id: string): Promise<Identities.Me<UserProfile>> {
    try {
      const identity = await this.auth.identities.getById(id)
      if (!identity) throwAuthError('AUTH_UNAUTHENTICATED')
      return identity
    } catch (error) {
      rethrowAuthError(error, 'AUTH_UNAUTHENTICATED')
    }
  }
}
