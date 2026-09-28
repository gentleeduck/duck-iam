import { nextSession } from '@gentleduck/auth/server/next'
import { auth } from '@/auth'

export const GET = nextSession(auth)
