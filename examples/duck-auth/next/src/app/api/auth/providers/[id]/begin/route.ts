import { nextProviderBegin } from '@gentleduck/auth/server/next'
import { auth } from '@/auth'

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }): Promise<Response> {
  return nextProviderBegin(auth, (await params).id)(req)
}
