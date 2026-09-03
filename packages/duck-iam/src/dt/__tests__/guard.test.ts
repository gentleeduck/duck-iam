import { afterEach, describe, expect, it } from 'vitest'
import { isDevtoolsAllowed } from '../lib/guard'
import type { IamIDevtoolsEngine } from '../lib/types'

function baseEngine(): IamIDevtoolsEngine {
  const notCalled = async (): Promise<never> => {
    throw new Error('the guard must not touch the engine beyond its mode')
  }
  return {
    admin: {
      assignRole: notCalled,
      export: notCalled,
      getAttributes: notCalled,
      getPolicy: notCalled,
      getRole: notCalled,
      listPolicies: notCalled,
      listRoles: notCalled,
      revokeRole: notCalled,
      setAttributes: notCalled,
    },
    can: notCalled,
    explain: notCalled,
    stats: {
      get() {
        return {}
      },
      reset() {},
    },
  }
}

/** How a concrete `Engine` actually surfaces its mode: a private `_mode` field. */
function engineInMode(mode: 'development' | 'production'): IamIDevtoolsEngine {
  return Object.assign(baseEngine(), { _mode: mode })
}

const original = process.env.NODE_ENV

afterEach(() => {
  process.env.NODE_ENV = original
})

/**
 * The panel is not read-only: it calls `assignRole`, `revokeRole` and
 * `setAttributes` with no auth of its own. `NODE_ENV=production` always
 * blocked, but the asymmetry ran one way - `NODE_ENV=development` beat an
 * explicit `mode: 'production'` engine, so a staging box left on
 * `NODE_ENV=development` mounted an unauthenticated role-assignment UI over a
 * production engine.
 */
describe('devtools guard: a production engine is an absolute block', () => {
  it('blocks a production engine even under NODE_ENV=development', () => {
    process.env.NODE_ENV = 'development'
    expect(isDevtoolsAllowed(engineInMode('production'))).toBe(false)
  })

  it('blocks a production engine under NODE_ENV=test', () => {
    process.env.NODE_ENV = 'test'
    expect(isDevtoolsAllowed(engineInMode('production'))).toBe(false)
  })

  it('blocks a production engine with no NODE_ENV at all', () => {
    process.env.NODE_ENV = undefined
    expect(isDevtoolsAllowed(engineInMode('production'))).toBe(false)
  })

  it('reads the mode from a public `mode` field too', () => {
    process.env.NODE_ENV = 'development'
    expect(isDevtoolsAllowed(Object.assign(baseEngine(), { mode: 'production' }))).toBe(false)
  })

  it('reads the mode from `config.mode` too', () => {
    process.env.NODE_ENV = 'development'
    expect(isDevtoolsAllowed(Object.assign(baseEngine(), { config: { mode: 'production' } }))).toBe(false)
  })

  // `isDevtoolsBlocked` used to live here as a "back-compat alias for external
  // callers", marked `@deprecated` in favour of the function nothing called.
  // `src/dt/index.ts` exported neither name and `package.json` publishes only
  // `./dt`, so there were no external callers for it to serve; the two internal
  // call sites now read `!isDevtoolsAllowed(...)`.
  it('blocks a production engine, which is what the two mount sites negate', () => {
    process.env.NODE_ENV = 'development'
    expect(isDevtoolsAllowed(engineInMode('production'))).toBe(false)
  })
})

describe('devtools guard: the signals that still allow', () => {
  it('allows a development engine with no NODE_ENV', () => {
    process.env.NODE_ENV = undefined
    expect(isDevtoolsAllowed(engineInMode('development'))).toBe(true)
  })

  it('allows a development engine under NODE_ENV=development', () => {
    process.env.NODE_ENV = 'development'
    expect(isDevtoolsAllowed(engineInMode('development'))).toBe(true)
  })

  it('allows an engine of unknown mode under NODE_ENV=development', () => {
    process.env.NODE_ENV = 'development'
    expect(isDevtoolsAllowed(baseEngine())).toBe(true)
  })

  it('still blocks an engine of unknown mode with no NODE_ENV', () => {
    process.env.NODE_ENV = undefined
    expect(isDevtoolsAllowed(baseEngine())).toBe(false)
  })

  it('still blocks a development engine under NODE_ENV=production', () => {
    process.env.NODE_ENV = 'production'
    expect(isDevtoolsAllowed(engineInMode('development'))).toBe(false)
  })
})
