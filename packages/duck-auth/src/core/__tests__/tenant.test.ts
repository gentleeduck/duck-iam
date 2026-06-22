import { describe, expect, it } from 'vitest'
import { authCurrentTenant, authResolveTenant, authWithTenant } from '../tenant'

describe('authWithTenant / authCurrentTenant / authResolveTenant', () => {
  it('authCurrentTenant is undefined outside a authWithTenant scope', () => {
    expect(authCurrentTenant()).toBeUndefined()
  })

  it('authWithTenant binds the tenantId inside the callback', async () => {
    let seen: string | undefined
    await authWithTenant('alice', async () => {
      seen = authCurrentTenant()?.tenantId
    })
    expect(seen).toBe('alice')
    // Scope ends on return.
    expect(authCurrentTenant()).toBeUndefined()
  })

  it('authWithTenant returns the callback result (sync + async)', async () => {
    const sync = authWithTenant('t1', () => 42)
    expect(sync).toBe(42)
    const async = await authWithTenant('t2', async () => 99)
    expect(async).toBe(99)
  })

  it('nested authWithTenant overrides the outer scope', async () => {
    let inner: string | undefined
    let outerAfter: string | undefined
    await authWithTenant('outer', async () => {
      await authWithTenant('inner', async () => {
        inner = authCurrentTenant()?.tenantId
      })
      outerAfter = authCurrentTenant()?.tenantId
    })
    expect(inner).toBe('inner')
    expect(outerAfter).toBe('outer')
  })

  it('authWithTenant(undefined) explicitly enters the global scope', async () => {
    await authWithTenant('alice', async () => {
      await authWithTenant(undefined, async () => {
        expect(authCurrentTenant()?.tenantId).toBeUndefined()
      })
      expect(authCurrentTenant()?.tenantId).toBe('alice')
    })
  })

  it('authResolveTenant prefers explicit caller-supplied context over ambient', async () => {
    await authWithTenant('ambient', async () => {
      expect(authResolveTenant().tenantId).toBe('ambient')
      expect(authResolveTenant({ tenantId: 'explicit' }).tenantId).toBe('explicit')
      // Empty explicit (no tenantId) falls back to ambient.
      expect(authResolveTenant({}).tenantId).toBe('ambient')
    })
  })

  it('async chains across awaits preserve the tenant scope', async () => {
    await authWithTenant('a', async () => {
      await new Promise((r) => setTimeout(r, 5))
      expect(authCurrentTenant()?.tenantId).toBe('a')
      // Promise.all branches inherit independently
      const results = await Promise.all([
        (async () => {
          await new Promise((r) => setTimeout(r, 3))
          return authCurrentTenant()?.tenantId
        })(),
        (async () => {
          await new Promise((r) => setTimeout(r, 1))
          return authCurrentTenant()?.tenantId
        })(),
      ])
      expect(results).toEqual(['a', 'a'])
    })
  })
})
