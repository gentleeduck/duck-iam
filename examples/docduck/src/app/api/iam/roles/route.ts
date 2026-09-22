/**
 * `GET /api/iam/roles` - every role definition, with its grants and
 * inheritance. `PUT /api/iam/roles` - upsert.
 */
import { iamAdminHandlers } from '@/lib/iam-admin'

export async function GET(request: Request) {
  return iamAdminHandlers.listRoles(request, { params: {} })
}

export async function PUT(request: Request) {
  return iamAdminHandlers.saveRole(request, { params: {} })
}
