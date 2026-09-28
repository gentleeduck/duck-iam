import { auth } from '@/auth'

export async function GET(): Promise<Response> {
  return Response.json({ providers: auth.providers.list() })
}
