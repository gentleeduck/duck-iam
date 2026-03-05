import { cookies } from 'next/headers'

export async function getCurrentUserId(): Promise<string | null> {
  const cookieStore = await cookies()
  const sessionCookie = cookieStore.get('session-user-id')
  return sessionCookie?.value ?? null
}
