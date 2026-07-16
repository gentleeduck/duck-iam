import { describe, expect, it } from 'vitest'
import { currentTenant, resolveTenant, withTenant } from '../tenant'

describe('authWithTenant / authCurrentTenant / authResolveTenant', () => {
  it('authCurrentTenant is undefined outside a authWithTenant scope', () => {
    expect(currentTenant()).toBeUndefined()
  })

  it('authWithTenant binds the tenantId inside the callback', async () => {
    let seen: string | undefined
    await withTenant('alice', async () => {
      seen = currentTenant()?.tenantId
    })
    expect(seen).toBe('alice')
    // Scope ends on return.
    expect(currentTenant()).toBeUndefined()
  })

  it('authWithTenant returns the callback result (sync + async)', async () => {
    const sync = withTenant('t1', () => 42)
    expect(sync).toBe(42)
    const async = await withTenant('t2', async () => 99)
    expect(async).toBe(99)
  })

  it('nested authWithTenant overrides the outer scope', async () => {
    let inner: string | undefined
    let outerAfter: string | undefined
    await withTenant('outer', async () => {
      await withTenant('inner', async () => {
        inner = currentTenant()?.tenantId
      })
      outerAfter = currentTenant()?.tenantId
    })
    expect(inner).toBe('inner')
    expect(outerAfter).toBe('outer')
  })

  it('authWithTenant(undefined) explicitly enters the global scope', async () => {
    await withTenant('alice', async () => {
      await withTenant(undefined, async () => {
        expect(currentTenant()?.tenantId).toBeUndefined()
      })
      expect(currentTenant()?.tenantId).toBe('alice')
    })
  })

  it('authResolveTenant prefers explicit caller-supplied context over ambient', async () => {
    await withTenant('ambient', async () => {
      expect(resolveTenant().tenantId).toBe('ambient')
      expect(resolveTenant({ tenantId: 'explicit' }).tenantId).toBe('explicit')
      // Empty explicit (no tenantId) falls back to ambient.
      expect(resolveTenant({}).tenantId).toBe('ambient')
    })
  })

  it('async chains across awaits preserve the tenant scope', async () => {
    await withTenant('a', async () => {
      await new Promise((r) => setTimeout(r, 5))
      expect(currentTenant()?.tenantId).toBe('a')
      // Promise.all branches inherit independently
      const results = await Promise.all([
        (async () => {
          await new Promise((r) => setTimeout(r, 3))
          return currentTenant()?.tenantId
        })(),
        (async () => {
          await new Promise((r) => setTimeout(r, 1))
          return currentTenant()?.tenantId
        })(),
      ])
      expect(results).toEqual(['a', 'a'])
    })
  })
})
