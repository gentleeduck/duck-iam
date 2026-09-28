import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import * as schema from './schema'

// A factory, not a singleton: each framework runs as its own process and needs its own Pool,
// even though every process points at the same DATABASE_URL.
export function createDb(connectionString = process.env.DATABASE_URL) {
  if (!connectionString) throw new Error('DATABASE_URL is not set (see .env.example)')
  const pool = new Pool({ connectionString })
  const db = drizzle(pool, { schema })
  return { pool, db }
}
