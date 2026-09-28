import { seedDb } from '@examples/duck-iam-shared/seed'
import { db, pool } from '.'

await seedDb(db)
await pool.end()
