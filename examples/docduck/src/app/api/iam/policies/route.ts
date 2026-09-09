/**
 * `GET /api/iam/policies` - every stored policy, for the devtools Policies
 * panel and for `engine.explain()` running in the browser.
 * `PUT /api/iam/policies` - upsert, which `IamHttpAdapter` uses on write.
 *
 * Both are duck-iam's own handlers; the wrappers exist only to give Next the
 * signature it types route exports against.
 */
import { iamAdminHandlers } from '@/lib/iam-admin'

export async function GET(request: Request) {
  return iamAdminHandlers.listPolicies(request, { params: {} })
}

export async function PUT(request: Request) {
  return iamAdminHandlers.savePolicy(request, { params: {} })
}
