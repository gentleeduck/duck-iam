import { DrizzleSqliteAdapter } from '@gentleduck/auth/adapters/drizzle/sqlite'
import type { UserProfile } from '../auth/auth.profile'
import { db } from '.'
import type * as schema from './schema'

export const authAdapter = new DrizzleSqliteAdapter<typeof schema, UserProfile>(db)
