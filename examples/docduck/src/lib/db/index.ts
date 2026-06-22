import { drizzle } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import * as schema from './schema'

const connectionString = process.env.DATABASE_URL ?? 'postgresql://docduck:docduck@localhost:5488/docduck'

const client = postgres(connectionString)
export const db = drizzle(client, { schema })
