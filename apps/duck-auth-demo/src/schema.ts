/**
 * Drizzle schema for duck-auth tables. Re-uses the bundled
 * @gentleduck/auth pg adapter tables so the bridge resolves them
 * 1:1 — no field divergence between adapter and migrations.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export {
  authCredentials as authCredentialsTable,
  authIdentities as authIdentitiesTable,
  authSessions as authSessionsTable,
} from '@gentleduck/auth/adapters/drizzle/pg'
