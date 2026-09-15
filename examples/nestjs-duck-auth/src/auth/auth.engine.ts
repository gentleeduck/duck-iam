import type { AuthEngine } from '@gentleduck/auth'
import { createAuth } from '@gentleduck/auth/core'
import { CookieTransport } from '@gentleduck/auth/core/transport'
import { memoryLimiter } from '@gentleduck/auth/limiters/memory'
import { passwords, ScryptHasher } from '@gentleduck/auth/providers/passwords'
import { authAdapter } from '../db/auth-adapter'
import type { UserProfile } from './auth.profile'

/** One definition, so the seed script and the running app cannot configure the engine differently. */
export function buildAuth(): AuthEngine<UserProfile> {
  return createAuth<UserProfile>({
    baseUrl: process.env.BASE_URL ?? 'http://localhost:3001',
    limiter: memoryLimiter({ max: 10, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher() })],
    session: {
      absoluteTtlMs: 1000 * 60 * 60 * 24 * 30,
      ttlMs: 1000 * 60 * 60 * 24 * 7,
    },
    stores: authAdapter,
    transport: new CookieTransport({
      name: 'duck-sid',
      path: '/',
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
    }),
  })
}
