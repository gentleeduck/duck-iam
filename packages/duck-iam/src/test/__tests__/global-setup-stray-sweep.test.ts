/**
 * The aged-stray sweep has to run even when this process starts no containers.
 *
 * Suites that own their own backends - `e2e-invalidation-redis.ts` starts both a
 * Redis and a Postgres of its own - label them `OWNED_LABEL` and start them
 * whether or not `globalSetup` starts anything. The sweep that collects those
 * after a crashed run used to sit *below* the `DUCKIAM_E2E_DATABASE_URL` early
 * return, so for anyone with that variable in `.env.test` - the normal local
 * setup - it never ran at all, and their orphans accumulated indefinitely.
 *
 * Nothing asserted the ordering, which is exactly why it could be wrong in
 * plain sight. These tests drive `setup()` with `execFile` stubbed, so they
 * assert what docker was actually asked to do without needing a daemon.
 */
import { describe, expect, it, vi } from 'vitest'

type Call = string[]

/** Load `e2e-containers.ts` with `child_process.execFile` replaced, capturing every docker argv. */
async function loadWithStubbedDocker(): Promise<{ calls: Call[]; setup: () => Promise<void> }> {
  const calls: Call[] = []
  vi.resetModules()
  vi.doMock('node:child_process', () => ({
    execFile: (_cmd: string, args: string[], _opts: unknown, cb: Function) => {
      calls.push(args)
      // `docker ps -aq` answers with no ids: nothing to remove, and the sweep
      // returns early rather than issuing an `rm` we would have to model.
      cb(null, { stdout: '', stderr: '' })
    },
  }))
  const mod = await import('../e2e-containers')
  return { calls, setup: mod.setup }
}

const isSweep = (c: Call) => c[0] === 'ps' && c.some((a) => a.startsWith('until='))
const isStart = (c: Call) => c[0] === 'run'

describe('globalSetup stray sweep', () => {
  it('sweeps aged owned strays even when DUCKIAM_E2E_DATABASE_URL is already set', async () => {
    vi.stubEnv('DUCKIAM_E2E_DATABASE_URL', 'postgres://someone-else/db')
    const { calls, setup } = await loadWithStubbedDocker()

    await setup()

    expect(calls.filter(isSweep), 'the sweep never ran, so a crashed run leaks forever').toHaveLength(1)
    vi.unstubAllEnvs()
  })

  it('starts nothing when the URL is already set - the sweep must not change that', async () => {
    vi.stubEnv('DUCKIAM_E2E_DATABASE_URL', 'postgres://someone-else/db')
    const { calls, setup } = await loadWithStubbedDocker()

    await setup()

    expect(calls.filter(isStart), 'deferring to a caller-supplied URL must still mean starting nothing').toEqual([])
    vi.unstubAllEnvs()
  })

  it('bounds the sweep by age, so a concurrent run is never collected', async () => {
    vi.stubEnv('DUCKIAM_E2E_DATABASE_URL', 'postgres://someone-else/db')
    const { calls, setup } = await loadWithStubbedDocker()

    await setup()

    const sweep = calls.find(isSweep)
    expect(sweep, 'no sweep issued').toBeDefined()
    // An unbounded `ps -aq --filter label=...` would match containers a
    // concurrent run started seconds ago and tear them down mid-suite.
    expect(sweep?.some((a) => a.startsWith('until='))).toBe(true)
    expect(sweep?.some((a) => a.startsWith('label=duck-iam-e2e-owned'))).toBe(true)
    vi.unstubAllEnvs()
  })

  it('sweeps before deferring, not after - ordering is the whole defect', async () => {
    vi.stubEnv('DUCKIAM_E2E_DATABASE_URL', 'postgres://someone-else/db')
    const { calls, setup } = await loadWithStubbedDocker()

    await setup()

    // With the sweep below the early return this list is empty, which is how
    // the bug survived: every other assertion about setup() still passed.
    expect(calls.map((c) => c[0])).toContain('ps')
    vi.unstubAllEnvs()
  })
})
