import { createAuthClient as authCreateClient } from 'better-auth/react'

export const authClient = authCreateClient({
  baseURL: process.env.NEXT_PUBLIC_BETTER_AUTH_URL ?? 'http://localhost:3005',
})

export const { signIn, signUp, signOut, useSession: authUseSession } = authClient
