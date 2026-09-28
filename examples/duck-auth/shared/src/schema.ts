// duck-auth's own pg tables, re-exported so `drizzle-kit generate` emits them from this one file.
export {
  authCredentials,
  authIdentities,
  authIdentityProviders,
  authSessions,
} from '@gentleduck/auth/adapters/drizzle/pg'
