import { signUp } from '@examples/duck-iam-shared/signup'
import { readBodyJson } from '@gentleduck/auth/server/generic'
import { auth, route } from '@/auth'
import { db } from '@/db'
import { getEngine } from '@/iam/iam'

export const POST = route(async (req) => {
  const body = await readBodyJson(req)
  const result = await signUp(auth, db, (id, companyId) => getEngine().admin.assignRole(id, 'admin', companyId), body)
  return Response.json(result, { status: 201 })
})
