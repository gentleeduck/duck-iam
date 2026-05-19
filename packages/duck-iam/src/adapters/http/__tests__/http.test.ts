import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { AccessControl, Adapter } from '../../../core/types'
import { HttpAdapter } from '../index'

type A = 'read' | 'write'
type R = 'post'
type Ro = 'editor'
type S = 'org-1'

interface RecordedCall {
  url: string
  init: RequestInit | undefined
}

function jsonResponse(body: unknown, ok = true, status = 200): Response {
  return {
    ok,
    status,
    text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
    json: async () => body,
  } as unknown as Response
}

function makeFetch(handler: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  const calls: RecordedCall[] = []
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init })
    return handler(url, init)
  })
  return { fetch: fetch as unknown as typeof globalThis.fetch, calls }
}

describe('HttpAdapter', () => {
  describe('config', () => {
    it('strips trailing slash from baseUrl', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse([]))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://api.example.com/access/', fetch })
      await adapter.listPolicies()
      expect(calls[0]?.url).toBe('https://api.example.com/access/policies')
    })

    it('merges static headers with content-type', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse([]))
      const adapter = new HttpAdapter<A, R, Ro, S>({
        baseUrl: 'https://api.example.com',
        fetch,
        headers: { authorization: 'Bearer xyz' },
      })
      await adapter.listPolicies()
      const headers = calls[0]?.init?.headers as Record<string, string>
      expect(headers['Content-Type']).toBe('application/json')
      expect(headers.authorization).toBe('Bearer xyz')
    })

    it('supports async header function', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse([]))
      const adapter = new HttpAdapter<A, R, Ro, S>({
        baseUrl: 'https://api.example.com',
        fetch,
        headers: async () => ({ 'x-tenant': 't1' }),
      })
      await adapter.listPolicies()
      const headers = calls[0]?.init?.headers as Record<string, string>
      expect(headers['x-tenant']).toBe('t1')
    })

    it('throws on non-ok response with status + body', async () => {
      const { fetch } = makeFetch(() => jsonResponse('boom', false, 500))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://api.example.com', fetch })
      await expect(adapter.listPolicies()).rejects.toThrow(/duck-iam HTTP 500: boom/)
    })

    it('rejects non-http(s) baseUrl scheme (SEC-001)', () => {
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'ftp://api.example.com/iam' })).toThrow(
        /scheme must be http: or https:/,
      )
    })

    it('rejects baseUrl with query string or fragment (SEC-001)', () => {
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://api.example.com/iam?x=1' })).toThrow(
        /query string or fragment/,
      )
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://api.example.com/iam#frag' })).toThrow(
        /query string or fragment/,
      )
    })

    it('rejects malformed baseUrl (SEC-001)', () => {
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'not a url' })).toThrow(/invalid baseUrl/)
    })

    it('rejects private/loopback host by default (SEC-001)', () => {
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'http://127.0.0.1/iam' })).toThrow(/private\/loopback/)
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'http://10.0.0.5/iam' })).toThrow(/private\/loopback/)
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'http://192.168.1.1/iam' })).toThrow(/private\/loopback/)
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'http://172.16.0.1/iam' })).toThrow(/private\/loopback/)
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'http://169.254.169.254/iam' })).toThrow(/private\/loopback/)
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'http://[::1]/iam' })).toThrow(/private\/loopback/)
    })

    it('rejects IPv4-mapped IPv6 loopback (SEC-028)', () => {
      // Node canonicalises `[::ffff:127.0.0.1]` -> `[::ffff:7f00:1]`, which
      // the bracket-strip + naive `::ffff:` recurse did not catch.
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'http://[::ffff:127.0.0.1]/iam' })).toThrow(
        /private\/loopback/,
      )
      // Canonical hex tail emitted by `new URL()`.
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'http://[::ffff:7f00:1]/iam' })).toThrow(/private\/loopback/)
      // RFC1918 mapped via ::ffff:.
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'http://[::ffff:c0a8:1]/iam' })).toThrow(/private\/loopback/)
      // Fully expanded form.
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'http://[0:0:0:0:0:ffff:7f00:1]/iam' })).toThrow(
        /private\/loopback/,
      )
    })

    it('accepts IPv4-mapped IPv6 loopback when allowPrivateHosts: true (SEC-028)', async () => {
      const { fetch } = makeFetch(() => jsonResponse([]))
      const adapter = new HttpAdapter<A, R, Ro, S>({
        allowPrivateHosts: true,
        baseUrl: 'http://[::ffff:127.0.0.1]/iam',
        fetch,
      })
      await expect(adapter.listPolicies()).resolves.toEqual([])
    })

    it('rejects IPv6 unspecified `::` (SEC-029)', () => {
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'http://[::]/iam' })).toThrow(/private\/loopback/)
    })

    it('accepts IPv6 unspecified when allowPrivateHosts: true (SEC-029)', async () => {
      const { fetch } = makeFetch(() => jsonResponse([]))
      const adapter = new HttpAdapter<A, R, Ro, S>({
        allowPrivateHosts: true,
        baseUrl: 'http://[::]/iam',
        fetch,
      })
      await expect(adapter.listPolicies()).resolves.toEqual([])
    })

    it('rejects IPv4 unspecified 0.0.0.0 (SEC-029)', () => {
      // Already covered by the `a === 0` arm; pin it explicitly so future
      // refactors can't silently drop the check.
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'http://0.0.0.0/iam' })).toThrow(/private\/loopback/)
    })

    it('accepts 0.0.0.0 when allowPrivateHosts: true (SEC-029)', async () => {
      const { fetch } = makeFetch(() => jsonResponse([]))
      const adapter = new HttpAdapter<A, R, Ro, S>({
        allowPrivateHosts: true,
        baseUrl: 'http://0.0.0.0/iam',
        fetch,
      })
      await expect(adapter.listPolicies()).resolves.toEqual([])
    })

    it('accepts private host when allowPrivateHosts: true (SEC-001)', async () => {
      const { fetch } = makeFetch(() => jsonResponse([]))
      const adapter = new HttpAdapter<A, R, Ro, S>({
        baseUrl: 'http://127.0.0.1/iam',
        fetch,
        allowPrivateHosts: true,
      })
      await expect(adapter.listPolicies()).resolves.toEqual([])
    })

    it('rejects baseUrl whose host is not in allowedHosts (SEC-001)', () => {
      expect(
        () =>
          new HttpAdapter<A, R, Ro, S>({
            baseUrl: 'https://evil.example.com/iam',
            allowedHosts: ['api.example.com'],
          }),
      ).toThrow(/not in allowedHosts/)
    })

    it('accepts baseUrl whose host is in allowedHosts (SEC-001)', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse([]))
      const adapter = new HttpAdapter<A, R, Ro, S>({
        baseUrl: 'https://api.example.com',
        fetch,
        allowedHosts: ['api.example.com'],
      })
      await adapter.listPolicies()
      expect(calls[0]?.url).toBe('https://api.example.com/policies')
    })

    it('matches allowedHosts case-insensitively when entry is uppercase (SEC-030)', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse([]))
      const adapter = new HttpAdapter<A, R, Ro, S>({
        baseUrl: 'https://api.example.com',
        fetch,
        allowedHosts: ['API.EXAMPLE.COM'],
      })
      await adapter.listPolicies()
      expect(calls[0]?.url).toBe('https://api.example.com/policies')
    })

    it('matches allowedHosts case-insensitively when URL host is mixed case (SEC-030)', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse([]))
      const adapter = new HttpAdapter<A, R, Ro, S>({
        baseUrl: 'https://API.Example.COM',
        fetch,
        allowedHosts: ['api.example.com'],
      })
      await adapter.listPolicies()
      // Adapter preserves the caller's original baseUrl casing in the
      // request URL; the SEC-030 fix only normalises for the allowlist
      // comparison.
      expect(calls[0]?.url).toBe('https://API.Example.COM/policies')
    })

    it('bare-host allowedHosts entry matches port-bearing URL (SEC-030)', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse([]))
      const adapter = new HttpAdapter<A, R, Ro, S>({
        baseUrl: 'https://api.example.com:8080',
        fetch,
        allowedHosts: ['api.example.com'],
      })
      await adapter.listPolicies()
      expect(calls[0]?.url).toBe('https://api.example.com:8080/policies')
    })

    it('host:port allowedHosts entry matches only that exact port (SEC-030)', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse([]))
      const adapter = new HttpAdapter<A, R, Ro, S>({
        baseUrl: 'https://api.example.com:8080',
        fetch,
        allowedHosts: ['api.example.com:8080'],
      })
      await adapter.listPolicies()
      expect(calls[0]?.url).toBe('https://api.example.com:8080/policies')

      expect(
        () =>
          new HttpAdapter<A, R, Ro, S>({
            baseUrl: 'https://api.example.com:9090',
            allowedHosts: ['api.example.com:8080'],
          }),
      ).toThrow(/not in allowedHosts/)
    })

    it('rejects 6to4 IPv6 wrapping loopback (SEC-035)', () => {
      // 2002:7f00:0001:: carries inner 127.0.0.1 via 6to4. Linux ships 6to4
      // by default; this used to slip past the IPv6 private check.
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'http://[2002:7f00:0001::]/iam' })).toThrow(
        /private\/loopback/,
      )
      // Compact form Node may emit.
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'http://[2002:7f00:1::]/iam' })).toThrow(/private\/loopback/)
    })

    it('rejects 6to4 IPv6 wrapping RFC1918 (SEC-035)', () => {
      // 2002:c0a8:0001:: carries inner 192.168.0.1.
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'http://[2002:c0a8:0001::]/iam' })).toThrow(
        /private\/loopback/,
      )
    })

    it('accepts 6to4 loopback when allowPrivateHosts: true (SEC-035)', async () => {
      const { fetch } = makeFetch(() => jsonResponse([]))
      const adapter = new HttpAdapter<A, R, Ro, S>({
        allowPrivateHosts: true,
        baseUrl: 'http://[2002:7f00:1::]/iam',
        fetch,
      })
      await expect(adapter.listPolicies()).resolves.toEqual([])
    })

    it('rejects NAT64 well-known prefix wrapping loopback (SEC-035)', () => {
      // 64:ff9b::/96 well-known NAT64 prefix; last 32 bits hold the inner v4.
      // `64:ff9b::7f00:1` → 127.0.0.1.
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'http://[64:ff9b::7f00:1]/iam' })).toThrow(
        /private\/loopback/,
      )
      // Dotted-quad tail spelling (also valid input form).
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'http://[64:ff9b::127.0.0.1]/iam' })).toThrow(
        /private\/loopback/,
      )
    })

    it('accepts NAT64 loopback when allowPrivateHosts: true (SEC-035)', async () => {
      const { fetch } = makeFetch(() => jsonResponse([]))
      const adapter = new HttpAdapter<A, R, Ro, S>({
        allowPrivateHosts: true,
        baseUrl: 'http://[64:ff9b::7f00:1]/iam',
        fetch,
      })
      await expect(adapter.listPolicies()).resolves.toEqual([])
    })

    it('canonical NAT64 form `[64:ff9b::7f00:1]` still rejects loopback (SEC-038)', () => {
      // SEC-038 regression: the `0064:ff9b:` literal branch had an off-by-one
      // slice; verify the canonical WHATWG form (which is what `new URL`
      // actually emits) continues to reject correctly.
      expect(() => new HttpAdapter<A, R, Ro, S>({ baseUrl: 'http://[64:ff9b::7f00:1]/iam' })).toThrow(
        /private\/loopback/,
      )
    })

    it('matches allowedHosts when URL has trailing FQDN dot (SEC-037)', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse([]))
      const adapter = new HttpAdapter<A, R, Ro, S>({
        baseUrl: 'https://api.example.com./iam',
        fetch,
        allowedHosts: ['api.example.com'],
      })
      await adapter.listPolicies()
      expect(calls[0]?.url).toBe('https://api.example.com./iam/policies')
    })

    it('matches when allowlist entry has trailing dot but URL does not (SEC-037)', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse([]))
      const adapter = new HttpAdapter<A, R, Ro, S>({
        baseUrl: 'https://api.example.com',
        fetch,
        allowedHosts: ['api.example.com.'],
      })
      await adapter.listPolicies()
      expect(calls[0]?.url).toBe('https://api.example.com/policies')
    })

    it('matches unicode allowlist entry against punycode URL host (SEC-037)', async () => {
      // Node's URL parser returns the punycode form for Unicode inputs.
      // An allowlist entry authored in Unicode must still match.
      const { fetch, calls } = makeFetch(() => jsonResponse([]))
      const adapter = new HttpAdapter<A, R, Ro, S>({
        baseUrl: 'https://xn--mnchen-3ya.de/iam',
        fetch,
        allowedHosts: ['münchen.de'],
      })
      await adapter.listPolicies()
      expect(calls[0]?.url).toBe('https://xn--mnchen-3ya.de/iam/policies')
    })

    it('encodes subject id path segment to defeat path injection (SEC-001)', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse([]))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      await adapter.getSubjectRoles('..//etc/passwd')
      expect(calls[0]?.url).toBe('https://x/subjects/..%2F%2Fetc%2Fpasswd/roles')
      expect(calls[0]?.url).not.toContain('/etc/passwd')
    })

    it('encodes policy id path segment (SEC-001)', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse(null, false, 404))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      await adapter.getPolicy('..//internal-admin')
      expect(calls[0]?.url).toBe('https://x/policies/..%2F%2Finternal-admin')
    })

    it('warns once when allowedHosts is omitted (SEC-001)', () => {
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
      try {
        // Latch is module-level: prior tests in this file may have already
        // tripped it. Construct several adapters and assert the spy fires at
        // most once across them.
        new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://a.example.com' })
        new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://b.example.com' })
        new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://c.example.com' })
        const allowedHostsCalls = warn.mock.calls.filter((c) => String(c[0] ?? '').includes('allowedHosts'))
        expect(allowedHostsCalls.length).toBeLessThanOrEqual(1)
      } finally {
        warn.mockRestore()
      }
    })

    it('uses globalThis.fetch when no fetch supplied', async () => {
      const original = globalThis.fetch
      const stub = vi.fn(async () => jsonResponse([]))
      globalThis.fetch = stub as unknown as typeof globalThis.fetch
      try {
        const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://api.example.com' })
        await adapter.listPolicies()
        expect(stub).toHaveBeenCalledOnce()
      } finally {
        globalThis.fetch = original
      }
    })
  })

  describe('Adapter.IPolicyStore', () => {
    const policy: AccessControl.IPolicy<A, R, Ro> = { id: 'p1', name: 'P', algorithm: 'deny-overrides', rules: [] }

    it('listPolicies GET /policies', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse([policy]))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      const out = await adapter.listPolicies()
      expect(out).toEqual([policy])
      expect(calls[0]?.url).toBe('https://x/policies')
    })

    it('getPolicy GET /policies/:id', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse(policy))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      const out = await adapter.getPolicy('p1')
      expect(out).toEqual(policy)
      expect(calls[0]?.url).toBe('https://x/policies/p1')
    })

    it('getPolicy returns null on 404', async () => {
      const { fetch } = makeFetch(() => jsonResponse('not found', false, 404))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      await expect(adapter.getPolicy('missing')).resolves.toBeNull()
    })

    it('getPolicy still throws on 5xx', async () => {
      const { fetch } = makeFetch(() => jsonResponse('boom', false, 503))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      await expect(adapter.getPolicy('p1')).rejects.toThrow(/duck-iam HTTP 503/)
    })

    it('savePolicy PUT /policies', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse({ ok: true }))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      await adapter.savePolicy(policy)
      expect(calls[0]?.url).toBe('https://x/policies')
      expect(calls[0]?.init?.method).toBe('PUT')
      expect(calls[0]?.init?.body).toBe(JSON.stringify(policy))
    })

    it('deletePolicy DELETE /policies/:id', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse({ ok: true }))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      await adapter.deletePolicy('p1')
      expect(calls[0]?.url).toBe('https://x/policies/p1')
      expect(calls[0]?.init?.method).toBe('DELETE')
    })
  })

  describe('Adapter.IRoleStore', () => {
    const role: AccessControl.IRole<A, R, Ro, S> = { id: 'editor', name: 'Editor', permissions: [] }

    it('listRoles GET /roles', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse([role]))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      const out = await adapter.listRoles()
      expect(out).toEqual([role])
      expect(calls[0]?.url).toBe('https://x/roles')
    })

    it('getRole GET /roles/:id', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse(role))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      await adapter.getRole('editor')
      expect(calls[0]?.url).toBe('https://x/roles/editor')
    })

    it('getRole returns null on 404', async () => {
      const { fetch } = makeFetch(() => jsonResponse('not found', false, 404))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      await expect(adapter.getRole('missing')).resolves.toBeNull()
    })

    it('saveRole PUT /roles', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse({ ok: true }))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      await adapter.saveRole(role)
      expect(calls[0]?.init?.method).toBe('PUT')
      expect(calls[0]?.init?.body).toBe(JSON.stringify(role))
    })

    it('deleteRole DELETE /roles/:id', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse({ ok: true }))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      await adapter.deleteRole('editor')
      expect(calls[0]?.url).toBe('https://x/roles/editor')
      expect(calls[0]?.init?.method).toBe('DELETE')
    })
  })

  describe('Adapter.ISubjectStore', () => {
    it('getSubjectRoles GET /subjects/:id/roles', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse(['editor']))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      const out = await adapter.getSubjectRoles('user-1')
      expect(out).toEqual(['editor'])
      expect(calls[0]?.url).toBe('https://x/subjects/user-1/roles')
    })

    it('getSubjectScopedRoles GET /subjects/:id/scoped-roles', async () => {
      const scoped = [{ role: 'editor', scope: 'org-1' }]
      const { fetch, calls } = makeFetch(() => jsonResponse(scoped))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      const out = await adapter.getSubjectScopedRoles('user-1')
      expect(out).toEqual(scoped)
      expect(calls[0]?.url).toBe('https://x/subjects/user-1/scoped-roles')
    })

    it('assignRole POST with body', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse({ ok: true }))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      await adapter.assignRole('user-1', 'editor', 'org-1')
      expect(calls[0]?.url).toBe('https://x/subjects/user-1/roles')
      expect(calls[0]?.init?.method).toBe('POST')
      expect(JSON.parse(calls[0]?.init?.body as string)).toEqual({ roleId: 'editor', scope: 'org-1' })
    })

    it('revokeRole DELETE without scope', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse({ ok: true }))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      await adapter.revokeRole('user-1', 'editor')
      expect(calls[0]?.url).toBe('https://x/subjects/user-1/roles/editor')
      expect(calls[0]?.init?.method).toBe('DELETE')
    })

    it('revokeRole DELETE encodes scope query', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse({ ok: true }))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      await adapter.revokeRole('user-1', 'editor', 'org one' as S)
      expect(calls[0]?.url).toBe('https://x/subjects/user-1/roles/editor?scope=org%20one')
    })

    it('getSubjectAttributes GET', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse({ team: 'A' }))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      const out = await adapter.getSubjectAttributes('user-1')
      expect(out).toEqual({ team: 'A' })
      expect(calls[0]?.url).toBe('https://x/subjects/user-1/attributes')
    })

    it('setSubjectAttributes PATCH with body', async () => {
      const { fetch, calls } = makeFetch(() => jsonResponse({ ok: true }))
      const adapter = new HttpAdapter<A, R, Ro, S>({ baseUrl: 'https://x', fetch })
      await adapter.setSubjectAttributes('user-1', { team: 'A' })
      expect(calls[0]?.init?.method).toBe('PATCH')
      expect(JSON.parse(calls[0]?.init?.body as string)).toEqual({ team: 'A' })
    })
  })

  describe('retry + circuit breaker (N8)', () => {
    it('retries on 5xx and succeeds within budget', async () => {
      let calls = 0
      const fetch = vi.fn(async () => {
        calls++
        return calls < 3 ? jsonResponse('boom', false, 503) : jsonResponse([])
      }) as unknown as typeof globalThis.fetch
      const adapter = new HttpAdapter<A, R, Ro, S>({
        baseUrl: 'https://x',
        fetch,
        retries: 3,
        backoffMs: 1,
        timeoutMs: 0,
      })
      const out = await adapter.listPolicies()
      expect(out).toEqual([])
      expect(calls).toBe(3)
    })

    it('does not retry on 4xx', async () => {
      let calls = 0
      const fetch = vi.fn(async () => {
        calls++
        return jsonResponse('nope', false, 403)
      }) as unknown as typeof globalThis.fetch
      const adapter = new HttpAdapter<A, R, Ro, S>({
        baseUrl: 'https://x',
        fetch,
        retries: 3,
        backoffMs: 1,
        timeoutMs: 0,
      })
      await expect(adapter.listPolicies()).rejects.toThrow(/403/)
      expect(calls).toBe(1)
    })

    it('opens the circuit after N consecutive transient failures and rejects fast', async () => {
      const fetch = vi.fn(async () => jsonResponse('boom', false, 503)) as unknown as typeof globalThis.fetch
      const adapter = new HttpAdapter<A, R, Ro, S>({
        baseUrl: 'https://x',
        fetch,
        retries: 0,
        timeoutMs: 0,
        circuitBreakerThreshold: 2,
        circuitBreakerCooldownMs: 1_000,
      })
      await expect(adapter.listPolicies()).rejects.toThrow(/503/)
      await expect(adapter.listPolicies()).rejects.toThrow(/503/)
      // Third attempt: circuit open, rejects before fetch is touched.
      const beforeCalls = (fetch as unknown as { mock: { calls: unknown[] } }).mock.calls.length
      await expect(adapter.listPolicies()).rejects.toThrow(/circuit open/)
      const afterCalls = (fetch as unknown as { mock: { calls: unknown[] } }).mock.calls.length
      expect(afterCalls).toBe(beforeCalls)
    })

    it('closes the circuit on the first half-open success', async () => {
      let nextResponseOk = false
      const fetch = vi.fn(async () =>
        nextResponseOk ? jsonResponse([]) : jsonResponse('boom', false, 503),
      ) as unknown as typeof globalThis.fetch
      const adapter = new HttpAdapter<A, R, Ro, S>({
        baseUrl: 'https://x',
        fetch,
        retries: 0,
        timeoutMs: 0,
        circuitBreakerThreshold: 1,
        circuitBreakerCooldownMs: 5,
      })
      await expect(adapter.listPolicies()).rejects.toThrow(/503/) // open
      await expect(adapter.listPolicies()).rejects.toThrow(/circuit open/) // still open
      await new Promise((r) => setTimeout(r, 10)) // cooldown elapses
      nextResponseOk = true
      const out = await adapter.listPolicies() // half-open probe succeeds -> closed
      expect(out).toEqual([])
      const out2 = await adapter.listPolicies() // closed, normal traffic
      expect(out2).toEqual([])
    })
  })
})
