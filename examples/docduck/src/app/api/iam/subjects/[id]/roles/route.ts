/**
 * `GET  /api/iam/subjects/:id/roles` - the subject's unscoped roles.
 * `POST /api/iam/subjects/:id/roles` - grant one, optionally scoped.
 *
 * The GET has no shipped handler. `IamHttpAdapter.getSubjectRoles` calls it on
 * every `engine.explain()` from the browser, so without it the Decision
 * Inspector resolves every subject as role-less and explains a deny that the
 * server would have allowed.
 */
import { adapter } from '@/lib/access'
import { iamAdminHandlers, iamAdminRoute } from '@/lib/iam-admin'

export async function GET(request: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params
  return iamAdminRoute(request, () => adapter.getSubjectRoles(id))
}

export async function POST(request: Request, ctx: { params: Promise<{ id: string }> }) {
  return iamAdminHandlers.assignRole(request, ctx)
}
