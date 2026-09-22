/**
 * `GET   /api/iam/subjects/:id/attributes` - the subject's attribute bag.
 * `PATCH /api/iam/subjects/:id/attributes` - shallow-merge a patch into it.
 *
 * Neither has a shipped handler. The GET is what feeds ABAC conditions when
 * `engine.explain()` runs in the browser, and the PATCH is what the devtools
 * Subjects panel writes through.
 */
import type { IamPrimitives } from '@gentleduck/iam'
import { engine } from '@/lib/access'
import { iamAdminRoute } from '@/lib/iam-admin'

/** Keys that would write through `Object.prototype` rather than into the bag. */
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

function isScalar(value: unknown): value is IamPrimitives.Scalar {
  return value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
}

function isAttributeValue(value: unknown): value is IamPrimitives.AttributeValue {
  if (isScalar(value)) return true
  if (Array.isArray(value)) return value.every(isScalar)
  if (typeof value !== 'object' || value === null) return false
  return Object.values(value).every(isScalar)
}

/**
 * Narrows a parsed request body to an attribute bag, or returns `null`.
 *
 * Refuses the whole bag rather than dropping the offending key. An attribute
 * that reads as *absent* retires every deny rule that tests it, so a bag that
 * is partly wrong is more dangerous than one that is rejected - the caller
 * gets a 400 and can see what they sent.
 */
function narrowAttributes(value: unknown): IamPrimitives.Attributes | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  const out: IamPrimitives.Attributes = {}
  for (const [key, entry] of Object.entries(value)) {
    if (FORBIDDEN_KEYS.has(key)) return null
    if (!isAttributeValue(entry)) return null
    Object.defineProperty(out, key, { configurable: true, enumerable: true, value: entry, writable: true })
  }
  return out
}

export async function GET(request: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params
  return iamAdminRoute(request, () => engine.admin.getAttributes(id))
}

export async function PATCH(request: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params
  return iamAdminRoute(request, async () => {
    let body: unknown
    try {
      body = await request.json()
    } catch {
      return Response.json({ error: 'Invalid JSON body' }, { status: 400 })
    }
    const attrs = narrowAttributes(body)
    if (attrs === null) {
      return Response.json({ error: 'Expected a flat object of scalar attribute values' }, { status: 400 })
    }
    await engine.admin.setAttributes(id, attrs)
    return { ok: true }
  })
}
