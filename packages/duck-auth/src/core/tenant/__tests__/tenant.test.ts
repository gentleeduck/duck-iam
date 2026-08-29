/**
 * Tenant scope is an AsyncLocalStorage binding, and every store call reads it to
 * decide which tenant's rows it may touch. That makes it a data-isolation
 * boundary implemented by a mechanism that is easy to lose track of: a value that
 * survives an `await` but not a callback, or that leaks out of a `Promise.all`
 * branch into its sibling, is a cross-tenant read.
 *
 * The cases below are the ways an async context is normally lost or leaked:
 * awaits, timers, microtasks, concurrent branches, thrown errors, nesting, and
 * callbacks scheduled inside a scope but run outside it.
 */
import { describe, expect, it } from 'vitest'
import { currentTenant, resolveTenant, withTenant } from '../tenant'

/** Yield to the macrotask queue, the harshest thing for a context to survive. */
const tick = () => new Promise((resolve) => setTimeout(resolve, 0))

describe('withTenant establishes a scope', () => {
  it('binds the tenant for the duration of a synchronous function', () => {
    withTenant('acme', () => {
      expect(currentTenant()).toEqual({ tenantId: 'acme' })
    })
  })

  it('returns whatever the function returns', () => {
    expect(withTenant('acme', () => 42)).toBe(42)
  })

  it('returns the promise from an async function', async () => {
    expect(await withTenant('acme', async () => 'value')).toBe('value')
  })

  it('binds an empty context when the tenant is undefined', () => {
    withTenant(undefined, () => {
      expect(currentTenant()).toEqual({})
    })
  })

  it('leaves no scope behind once it returns', async () => {
    await withTenant('acme', async () => undefined)
    expect(currentTenant()).toBeUndefined()
  })
})

describe('the scope survives asynchrony', () => {
  it('survives a single await', async () => {
    await withTenant('acme', async () => {
      await Promise.resolve()
      expect(currentTenant()).toEqual({ tenantId: 'acme' })
    })
  })

  it('survives many awaits in a row', async () => {
    await withTenant('acme', async () => {
      for (let i = 0; i < 20; i++) {
        await Promise.resolve()
        expect(currentTenant()?.tenantId).toBe('acme')
      }
    })
  })

  it('survives a macrotask boundary', async () => {
    await withTenant('acme', async () => {
      await tick()
      expect(currentTenant()?.tenantId).toBe('acme')
    })
  })

  it('survives a nested helper several frames deep', async () => {
    const deep = async (n: number): Promise<string | undefined> => {
      if (n === 0) {
        await tick()
        return currentTenant()?.tenantId
      }
      return deep(n - 1)
    }
    expect(await withTenant('acme', () => deep(10))).toBe('acme')
  })

  it('is visible inside a callback scheduled within the scope', async () => {
    const seen = await withTenant(
      'acme',
      () =>
        new Promise<string | undefined>((resolve) => {
          setTimeout(() => resolve(currentTenant()?.tenantId), 0)
        }),
    )
    expect(seen).toBe('acme')
  })
})

describe('concurrent scopes do not bleed into each other', () => {
  it('keeps two parallel branches separate', async () => {
    // The failure this guards: one branch awaits, the other runs, and the first
    // resumes holding the second's tenant. That is a cross-tenant read.
    const [a, b] = await Promise.all([
      withTenant('alpha', async () => {
        await tick()
        return currentTenant()?.tenantId
      }),
      withTenant('beta', async () => {
        await tick()
        return currentTenant()?.tenantId
      }),
    ])
    expect(a).toBe('alpha')
    expect(b).toBe('beta')
  })

  it('keeps fifty interleaved branches separate', async () => {
    const results = await Promise.all(
      Array.from({ length: 50 }, (_, i) =>
        withTenant(`tenant-${i}`, async () => {
          await tick()
          await Promise.resolve()
          return currentTenant()?.tenantId
        }),
      ),
    )
    expect(results).toEqual(Array.from({ length: 50 }, (_, i) => `tenant-${i}`))
  })

  it('keeps a scoped branch separate from an unscoped one', async () => {
    const scoped = withTenant('acme', async () => {
      await tick()
      return currentTenant()?.tenantId
    })
    const unscoped = (async () => {
      await tick()
      return currentTenant()
    })()
    expect(await scoped).toBe('acme')
    expect(await unscoped).toBeUndefined()
  })

  it('a slow branch does not adopt a fast branch’s tenant', async () => {
    const slow = withTenant('slow', async () => {
      await new Promise((r) => setTimeout(r, 20))
      return currentTenant()?.tenantId
    })
    for (let i = 0; i < 10; i++) {
      await withTenant(`fast-${i}`, async () => {
        await tick()
      })
    }
    expect(await slow).toBe('slow')
  })
})

describe('nesting', () => {
  it('an inner scope shadows the outer one', () => {
    withTenant('outer', () => {
      withTenant('inner', () => {
        expect(currentTenant()?.tenantId).toBe('inner')
      })
    })
  })

  it('the outer scope is restored when the inner one returns', () => {
    withTenant('outer', () => {
      withTenant('inner', () => undefined)
      expect(currentTenant()?.tenantId).toBe('outer')
    })
  })

  it('restores the outer scope across an await too', async () => {
    await withTenant('outer', async () => {
      await withTenant('inner', async () => {
        await tick()
      })
      await tick()
      expect(currentTenant()?.tenantId).toBe('outer')
    })
  })

  it('an inner undefined scope hides the outer tenant rather than inheriting it', () => {
    // Worth pinning: `withTenant(undefined, ...)` binds an empty context, so it
    // is a way to drop out of a tenant, not a no-op that keeps the current one.
    withTenant('outer', () => {
      withTenant(undefined, () => {
        expect(currentTenant()).toEqual({})
      })
    })
  })
})

describe('errors do not strand the scope', () => {
  it('a throw inside the scope propagates and leaves nothing bound', () => {
    expect(() =>
      withTenant('acme', () => {
        throw new Error('boom')
      }),
    ).toThrow('boom')
    expect(currentTenant()).toBeUndefined()
  })

  it('a rejection inside the scope propagates and leaves nothing bound', async () => {
    await expect(
      withTenant('acme', async () => {
        await tick()
        throw new Error('boom')
      }),
    ).rejects.toThrow('boom')
    expect(currentTenant()).toBeUndefined()
  })

  it('a rejection in one branch does not disturb its sibling', async () => {
    const results = await Promise.allSettled([
      withTenant('good', async () => {
        await tick()
        return currentTenant()?.tenantId
      }),
      withTenant('bad', async () => {
        await tick()
        throw new Error('boom')
      }),
    ])
    expect(results[0]).toMatchObject({ status: 'fulfilled', value: 'good' })
    expect(results[1]?.status).toBe('rejected')
  })
})

describe('resolveTenant picks the effective context', () => {
  it('returns an empty context with nothing bound and nothing passed', () => {
    expect(resolveTenant()).toEqual({})
  })

  it('falls back to the ambient scope when no override is passed', () => {
    withTenant('ambient', () => {
      expect(resolveTenant()).toEqual({ tenantId: 'ambient' })
    })
  })

  it('an explicit override wins over the ambient scope', () => {
    // Documented as a default rather than a fence: a caller can deliberately
    // reach across tenants for one call.
    withTenant('ambient', () => {
      expect(resolveTenant({ tenantId: 'explicit' })).toEqual({ tenantId: 'explicit' })
    })
  })

  it('an override with an undefined tenantId falls through to the ambient', () => {
    withTenant('ambient', () => {
      expect(resolveTenant({ tenantId: undefined })).toEqual({ tenantId: 'ambient' })
    })
  })

  it('an empty override object falls through to the ambient', () => {
    withTenant('ambient', () => {
      expect(resolveTenant({})).toEqual({ tenantId: 'ambient' })
    })
  })

  it('an explicit empty-string tenant is honoured rather than treated as absent', () => {
    // Pinned because it is the one value that is present but falsy: the guard is
    // `!== undefined`, so an empty string overrides the ambient scope.
    withTenant('ambient', () => {
      expect(resolveTenant({ tenantId: '' })).toEqual({ tenantId: '' })
    })
  })

  it('resolves the same way across an await', async () => {
    await withTenant('ambient', async () => {
      await tick()
      expect(resolveTenant()).toEqual({ tenantId: 'ambient' })
      expect(resolveTenant({ tenantId: 'other' })).toEqual({ tenantId: 'other' })
    })
  })
})

describe('tenant identifiers are opaque strings', () => {
  it('keeps whatever string it was given, without trimming or folding case', () => {
    for (const id of ['Acme', 'ACME', ' acme ', 'acme:prod', "'; DROP TABLE x; --", '🦆', 'a'.repeat(500)]) {
      withTenant(id, () => {
        expect(currentTenant()?.tenantId).toBe(id)
      })
    }
  })

  it('treats identifiers differing only by case as different tenants', () => {
    withTenant('Acme', () => {
      expect(currentTenant()?.tenantId).not.toBe('acme')
    })
  })
})
