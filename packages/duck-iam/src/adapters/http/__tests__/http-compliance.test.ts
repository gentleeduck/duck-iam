import type { AccessControl, IamPrimitives } from '../../../core/types'
import { runAdapterCompliance } from '../../__compliance__/compliance'
import { IamHttpAdapter } from '../index'

/**
 * Reference implementation of the REST contract `IamHttpAdapter` speaks. The
 * compliance matrix runs the adapter against this server so the HTTP backend
 * is held to the same cross-backend semantics as memory/file/redis - in
 * particular that `GET /subjects/:id/roles` returns UNSCOPED roles only.
 */
function makeReferenceServer(): typeof globalThis.fetch {
  const policies = new Map<string, AccessControl.IPolicy>()
  const roles = new Map<string, AccessControl.IRole>()
  const assignments = new Map<string, Array<{ role: string; scope?: string }>>()
  const attributes = new Map<string, IamPrimitives.Attributes>()

  const json = (body: unknown, status = 200): Response =>
    ({
      json: async () => body,
      ok: status >= 200 && status < 300,
      status,
      text: async () => JSON.stringify(body),
    }) as unknown as Response

  return (async (input: string, init?: RequestInit) => {
    const url = new URL(input)
    const method = init?.method ?? 'GET'
    // baseUrl carries an `/access` mount prefix; strip it before routing.
    const segments = url.pathname.split('/').filter((s) => s.length > 0)
    if (segments[0] === 'access') segments.shift()
    const body: unknown = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined

    // /policies and /policies/:id
    if (segments[0] === 'policies') {
      const id = segments[1] === undefined ? undefined : decodeURIComponent(segments[1])
      if (method === 'GET' && id === undefined) return json([...policies.values()])
      if (method === 'GET' && id !== undefined) {
        const hit = policies.get(id)
        return hit ? json(hit) : json({ error: 'not found' }, 404)
      }
      if (method === 'PUT') {
        const policy = body as AccessControl.IPolicy
        policies.set(policy.id, policy)
        return json({})
      }
      if (method === 'DELETE' && id !== undefined) {
        policies.delete(id)
        return json({})
      }
    }

    // /roles and /roles/:id
    if (segments[0] === 'roles') {
      const id = segments[1] === undefined ? undefined : decodeURIComponent(segments[1])
      if (method === 'GET' && id === undefined) return json([...roles.values()])
      if (method === 'GET' && id !== undefined) {
        const hit = roles.get(id)
        return hit ? json(hit) : json({ error: 'not found' }, 404)
      }
      if (method === 'PUT') {
        const role = body as AccessControl.IRole
        roles.set(role.id, role)
        return json({})
      }
      if (method === 'DELETE' && id !== undefined) {
        roles.delete(id)
        return json({})
      }
    }

    // /subjects/:id/...
    if (segments[0] === 'subjects' && segments[1] !== undefined) {
      const subjectId = decodeURIComponent(segments[1])
      const entries = assignments.get(subjectId) ?? []

      if (segments[2] === 'roles' && segments[3] === undefined) {
        // Contract: unscoped roles only. Scoped ones go to /scoped-roles.
        if (method === 'GET') return json([...new Set(entries.filter((e) => e.scope == null).map((e) => e.role))])
        if (method === 'POST') {
          const roleId = String((body as { roleId: string }).roleId)
          const scope = (body as { scope?: string }).scope
          if (!entries.some((e) => e.role === roleId && e.scope === scope)) entries.push({ role: roleId, scope })
          assignments.set(subjectId, entries)
          return json({})
        }
      }
      if (segments[2] === 'roles' && segments[3] !== undefined && method === 'DELETE') {
        const roleId = decodeURIComponent(segments[3])
        const scope = url.searchParams.get('scope')
        assignments.set(
          subjectId,
          scope === null
            ? entries.filter((e) => e.role !== roleId)
            : entries.filter((e) => !(e.role === roleId && e.scope === scope)),
        )
        return json({})
      }
      if (segments[2] === 'scoped-roles' && method === 'GET') {
        return json(entries.filter((e) => e.scope != null).map((e) => ({ role: e.role, scope: e.scope })))
      }
      if (segments[2] === 'attributes') {
        if (method === 'GET') return json(attributes.get(subjectId) ?? {})
        if (method === 'PATCH') {
          attributes.set(subjectId, { ...(attributes.get(subjectId) ?? {}), ...(body as IamPrimitives.Attributes) })
          return json({})
        }
      }
    }

    return json({ error: `unhandled ${method} ${url.pathname}` }, 404)
  }) as unknown as typeof globalThis.fetch
}

runAdapterCompliance(
  'IamHttpAdapter',
  () =>
    new IamHttpAdapter({
      allowedHosts: ['iam.example.com'],
      baseUrl: 'https://iam.example.com/access',
      fetch: makeReferenceServer(),
      timeoutMs: 0,
    }),
)
