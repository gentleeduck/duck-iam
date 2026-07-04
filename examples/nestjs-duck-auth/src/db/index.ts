import { Database } from 'bun:sqlite'
import { resolve } from 'node:path'
import { drizzle } from 'drizzle-orm/bun-sqlite'
import * as schema from './schema'

const dbPath = resolve(import.meta.dir, '../../data.db')
export const sqlite = new Database(dbPath)
export const db = drizzle({ client: sqlite, schema })
