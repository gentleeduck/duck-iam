/**
 * `GET /api/iam/subjects/:id/scoped-roles` - the subject's `(role, scope)`
 * pairs.
 *
 * docduck's assignments are all workspace-scoped, so this is where the
 * devtools sees a subject's actual memberships; the unscoped list next door is
 * usually empty.
 */
import { adapter } from '@/lib/access'
import { iamAdminRoute } from '@/lib/iam-admin'

export async function GET(request: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params
  return iamAdminRoute(request, () => adapter.getSubjectScopedRoles(id))
}
