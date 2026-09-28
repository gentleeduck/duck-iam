import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import * as schema from './schema'

export type AppDb = NodePgDatabase<typeof schema>

// A factory, not a singleton: each backend runs as its own process and needs its own Pool,
// even though every process points at the same DATABASE_URL.
export function createDb(connectionString = process.env.DATABASE_URL) {
  if (!connectionString) throw new Error('DATABASE_URL is not set (see .env.example)')
  const pool = new Pool({ connectionString })
  const db: AppDb = drizzle(pool, { schema })
  return { pool, db }
}
