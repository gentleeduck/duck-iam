import { nextSignOut } from '@gentleduck/auth/server/next'
import { auth } from '@/auth'

export const POST = nextSignOut(auth)
