/**
 * `DELETE /api/iam/subjects/:id/roles/:roleId[?scope=]` - revoke one grant.
 *
 * Written out rather than delegated to `iamAdminHandlers.revokeRole`, which
 * drops the `?scope=` query parameter that `IamHttpAdapter.revokeRole` sends.
 * That matters here more than in most apps: docduck assigns every role with a
 * workspace scope, so a revoke that forgets the scope looks for an unscoped
 * row, finds none, and reports success having changed nothing.
 */
import { engine } from '@/lib/access'
import { iamAdminRoute } from '@/lib/iam-admin'

export async function DELETE(request: Request, ctx: { params: Promise<{ id: string; roleId: string }> }) {
  const { id, roleId } = await ctx.params
  const scope = new URL(request.url).searchParams.get('scope')
  return iamAdminRoute(request, async () => {
    await engine.admin.revokeRole(id, roleId, scope ?? undefined)
    return { ok: true }
  })
}
