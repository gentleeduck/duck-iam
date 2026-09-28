import { nextSignIn } from '@gentleduck/auth/server/next'
import { auth } from '@/auth'

export const POST = nextSignIn(auth)
