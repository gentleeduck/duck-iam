import { beginProvider } from '@examples/duck-auth-shared/routes'
import { executeIntents, readBodyJson } from '@gentleduck/auth/server/generic'
import { auth, route } from '@/auth'

export const POST = route(async (req: Request, { params }: { params: Promise<{ id: string }> }) =>
  executeIntents(await beginProvider(auth, (await params).id, await readBodyJson(req))),
)
