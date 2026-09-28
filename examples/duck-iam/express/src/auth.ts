import { buildAuth } from '@examples/duck-iam-shared/auth'
import { db } from './db'

export const auth = buildAuth(db)
