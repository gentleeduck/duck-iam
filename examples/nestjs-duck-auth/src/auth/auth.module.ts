import 'reflect-metadata'
import { AuthEngine } from '@gentleduck/auth'
import { authCreateSqlStores } from '@gentleduck/auth/adapters/sql'
import { AuthCookieTransport } from '@gentleduck/auth/core/transport'
import { AuthMemoryLimiter } from '@gentleduck/auth/limiters/memory'
import { authPassword } from '@gentleduck/auth/providers/password'
import { DUCK_AUTH_TOKEN } from '@gentleduck/auth/server/nestjs'
import { Global, Module, type Provider } from '@nestjs/common'
import { db } from '../db'
import { createAuthDrizzleBunSqliteBridge } from '../db/auth-bridge'
import { AuthController } from './auth.controller'
import { DuckAuthGuard } from './auth.guard'
import { AuthService } from './auth.service'

export { DUCK_AUTH_TOKEN }

interface UserProfile {
  email: string
  name: string
}

function createAuth(): AuthEngine<UserProfile> {
  const bridge = createAuthDrizzleBunSqliteBridge(db)
  const stores = authCreateSqlStores<UserProfile>(bridge)

  const auth = new AuthEngine<UserProfile>({
    baseUrl: process.env.BASE_URL ?? 'http://localhost:3001',
    transport: new AuthCookieTransport({
      name: 'duck-sid',
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
    }),
    stores,
    limiter: new AuthMemoryLimiter({ max: 10, windowMs: 60_000 }),
    session: {
      ttlMs: 1000 * 60 * 60 * 24 * 7,
      absoluteTtlMs: 1000 * 60 * 60 * 24 * 30,
    },
  })

  auth.providers.register(
    authPassword<UserProfile>({
      findIdentityByEmail: (email) => stores.identities.findByEmail(email, {}),
      passwords: auth.passwords,
    }),
  )

  return auth
}

const engineProvider: Provider = {
  provide: DUCK_AUTH_TOKEN,
  useFactory: () => createAuth(),
}

@Global()
@Module({
  providers: [engineProvider, AuthService, DuckAuthGuard],
  controllers: [AuthController],
  exports: [DUCK_AUTH_TOKEN, AuthService, DuckAuthGuard],
})
export class AuthModule {}
