/**
 * E2E: operator hooks that misbehave, against a REAL Postgres.
 *
 * A hook is code the engine did not write, running inside the authorization
 * path. The rule that matters: a throwing, garbage-returning or never-resolving
 * hook must never turn a deny into an allow. Everything else - a lost
 * diagnostic, a swallowed metric - is secondary.
 *
 * Every case is run against a live database with a real allow and a real deny
 * in it, so a "deny" here is a verdict and not an artefact of the fixture being
 * empty. The suite owns its own container.
 */
import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { createServer } from 'node:net'
import { promisify } from 'node:util'
import { and, eq, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { IamDrizzleAdapter } from '../../../adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '../../../adapters/drizzle/pg'
import { applyPgSchema } from '../../../test/e2e-env'
import type { AccessControl, IamRequest } from '../../types'
import { IamEngine } from '../engine'
import type { IamEngineTypes } from '../engine.types'

const exec = promisify(execFile)

const PG_IMAGE = 'postgres:16-alpine'
const PG_USER = 'duckiam'
const PG_PASSWORD = 'duckiam'
const PG_DB = 'duckiam_hooks'
const READY_TIMEOUT_MS = 90_000

async function docker(args: string[], timeout = 90_000): Promise<string> {
  const { stdout } = await exec('docker', args, { encoding: 'utf8', timeout })
  return stdout.trim()
}

async function freePort(): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const srv = createServer()
    srv.once('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address()
      if (addr === null || typeof addr === 'string') {
        srv.close()
        reject(new Error('could not allocate a port'))
        return
      }
      const { port } = addr
      srv.close(() => resolve(port))
    })
  })
}

async function waitUntilReady(name: string, probe: string[]): Promise<void> {
  const deadline = Date.now() + READY_TIMEOUT_MS
  let last = ''
  while (Date.now() < deadline) {
    try {
      await docker(['exec', name, ...probe], 15_000)
      return
    } catch (err) {
      last = err instanceof Error ? err.message : String(err)
      await new Promise((r) => setTimeout(r, 250))
    }
  }
  throw new Error(`${name} never became ready: ${last}`)
}

const TABLES = { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles }
const OPS = { and, eq, or }
type Hooks = IamEngineTypes.IHooks<string, string, string>

let containerName = ''
let url = ''
let fixturePool: Pool
const pools: Pool[] = []

function engineWith(hooks: Hooks, opts: { adapterTimeoutMs?: number } = {}) {
  const pool = new Pool({ connectionString: url })
  pool.on('error', () => {})
  pools.push(pool)
  return new IamEngine<string, string, string, string, 'development'>({
    adapter: new IamDrizzleAdapter<string, string, string, string>({ db: drizzle(pool), ops: OPS, tables: TABLES }),
    adapterTimeoutMs: opts.adapterTimeoutMs ?? 3000,
    cacheTTL: 0,
    hooks,
    mode: 'development',
  })
}

const DOC = { attributes: {}, type: 'doc' } as const
const SECRET = { attributes: {}, type: 'secret' } as const

beforeAll(async () => {
  await docker(['info', '--format', '{{.ServerVersion}}'], 10_000)
  containerName = `duck-iam-resilience-hooks-${randomBytes(4).toString('hex')}`
  const port = await freePort()
  await docker([
    'run',
    '-d',
    '--name',
    containerName,
    '--label',
    'duck-iam-e2e-owned',
    '-p',
    `127.0.0.1:${port}:5432`,
    '-e',
    `POSTGRES_USER=${PG_USER}`,
    '-e',
    `POSTGRES_PASSWORD=${PG_PASSWORD}`,
    '-e',
    `POSTGRES_DB=${PG_DB}`,
    PG_IMAGE,
  ])
  await waitUntilReady(containerName, ['pg_isready', '-U', PG_USER, '-d', PG_DB])
  await waitUntilReady(containerName, ['psql', '-U', PG_USER, '-d', PG_DB, '-c', 'SELECT 1'])
  url = `postgres://${PG_USER}:${PG_PASSWORD}@127.0.0.1:${port}/${PG_DB}`
  fixturePool = new Pool({ connectionString: url })
  fixturePool.on('error', () => {})
  await applyPgSchema(fixturePool)

  // `u1` may read `doc` and may not touch `secret`. Both verdicts are real.
  const boot = engineWith({}, { adapterTimeoutMs: 15_000 })
  await boot.admin.saveRole({ id: 'admin', name: 'admin', permissions: [{ action: 'read', resource: 'doc' }] })
  await boot.admin.assignRole('u1', 'admin')
  expect(await boot.can('u1', 'read', DOC)).toBe(true)
  expect(await boot.can('u1', 'read', SECRET)).toBe(false)
}, 180_000)

afterAll(async () => {
  await Promise.all(pools.map((p) => p.end().catch(() => {})))
  await fixturePool?.end().catch(() => {})
  if (containerName) await docker(['rm', '-f', '-v', containerName]).catch(() => {})
}, 120_000)

/** Every hook throwing at once: nothing may become an allow because of it. */
const THROW_ALL: Hooks = {
  afterEvaluate() {
    throw new Error('afterEvaluate exploded')
  },
  beforeEvaluate(req) {
    void req
    throw new Error('beforeEvaluate exploded')
  },
  onDeny() {
    throw new Error('onDeny exploded')
  },
  onError() {
    throw new Error('onError exploded')
  },
  onMetrics() {
    throw new Error('onMetrics exploded')
  },
  onPolicyError() {
    throw new Error('onPolicyError exploded')
  },
}

describe('E2E fail-closed: a throwing hook', () => {
  it('a throwing beforeEvaluate denies a request that would otherwise ALLOW', async () => {
    const engine = engineWith(THROW_ALL)
    const d = await engine.check('u1', 'read', DOC)
    console.info(`[resilience] beforeEvaluate throws on an allowable request: ${d.allowed ? 'ALLOW' : 'deny'}`)
    expect(d.allowed).toBe(false)
    expect(d.failure).toBe('evaluation')
  }, 60_000)

  it('a throwing beforeEvaluate denies every entry of a batch', async () => {
    const engine = engineWith(THROW_ALL)
    const map = await engine.permissions('u1', [
      { action: 'read', resource: 'doc' },
      { action: 'read', resource: 'secret' },
    ])
    expect(Object.values(map)).toEqual([false, false])
  }, 60_000)

  it('a throwing afterEvaluate/onDeny cannot rewrite a deny into an allow', async () => {
    const engine = engineWith({
      afterEvaluate() {
        throw new Error('afterEvaluate exploded')
      },
      onDeny() {
        throw new Error('onDeny exploded')
      },
      onMetrics() {
        throw new Error('onMetrics exploded')
      },
    })
    const d = await engine.check('u1', 'read', SECRET)
    expect(d.allowed).toBe(false)
    // And the legitimate allow is not corrupted into a deny either.
    expect((await engine.check('u1', 'read', DOC)).allowed).toBe(true)
  }, 60_000)

  it('a throwing onError, on top of a dead backend, still denies', async () => {
    // The database is fine; the *adapter* is pointed at a port nothing listens
    // on, which is what an operator sees when the database moves.
    const dead = await freePort()
    const pool = new Pool({ connectionString: `postgres://${PG_USER}:${PG_PASSWORD}@127.0.0.1:${dead}/${PG_DB}` })
    pool.on('error', () => {})
    pools.push(pool)
    const engine = new IamEngine<string, string, string, string, 'development'>({
      adapter: new IamDrizzleAdapter<string, string, string, string>({ db: drizzle(pool), ops: OPS, tables: TABLES }),
      adapterTimeoutMs: 1000,
      cacheTTL: 0,
      hooks: THROW_ALL,
      mode: 'development',
    })

    const d = await engine.check('u1', 'read', DOC)
    expect(d.allowed).toBe(false)
    expect(await engine.can('u1', 'read', DOC)).toBe(false)
    const map = await engine.permissions('u1', [{ action: 'read', resource: 'doc' }])
    expect(Object.values(map)).toEqual([false])
  }, 60_000)
})

describe('E2E fail-closed: a beforeEvaluate that returns garbage', () => {
  /**
   * Each of these is a deliberately malformed return value: the cast exists so
   * the test can hand the engine something the type system forbids, which is
   * exactly what an untyped JS caller or a hook reading from config can do.
   */
  const garbage: { name: string; value: unknown }[] = [
    { name: 'null', value: null },
    { name: 'undefined', value: undefined },
    { name: 'a string', value: 'nope' },
    { name: 'an empty object', value: {} },
    { name: 'a request with no subject', value: { action: 'read', resource: DOC } },
    { name: 'a request whose subject has no roles', value: { action: 'read', resource: DOC, subject: { id: 'u1' } } },
    {
      name: 'a request whose roles is a string',
      value: { action: 'read', resource: DOC, subject: { attributes: {}, id: 'u1', roles: 'admin' } },
    },
    {
      name: 'a request whose resource is missing',
      value: { action: 'read', subject: { attributes: {}, id: 'u1', roles: ['admin'] } },
    },
  ]

  for (const { name, value } of garbage) {
    it(`denies when beforeEvaluate returns ${name}`, async () => {
      const engine = engineWith({
        // Deliberately malformed: the cast manufactures the bad value.
        beforeEvaluate: () => value as IamRequest.IAccessRequest<string, string, string>,
      })
      const d = await engine.check('u1', 'read', DOC)
      console.info(`[resilience] beforeEvaluate returns ${name}: ${d.allowed ? 'ALLOW' : 'deny'}`)
      expect(d.allowed, `beforeEvaluate returning ${name} must not produce an allow`).toBe(false)
    }, 60_000)
  }

  it('a rejected beforeEvaluate promise denies', async () => {
    const engine = engineWith({ beforeEvaluate: () => Promise.reject(new Error('async hook failed')) })
    const d = await engine.check('u1', 'read', DOC)
    expect(d.allowed).toBe(false)
  }, 60_000)

  it('records what a beforeEvaluate that rewrites the subject actually does', async () => {
    // Documented behaviour: the hook may modify the request, and the engine
    // honours it. Recorded here so the blast radius of a compromised hook is
    // written down rather than assumed.
    const engine = engineWith({
      beforeEvaluate: (req) => ({ ...req, resource: { attributes: {}, type: 'doc' } }),
    })
    const d = await engine.check('u1', 'read', SECRET)
    console.info(`[resilience] beforeEvaluate rewrote resource secret -> doc: ${d.allowed ? 'ALLOW' : 'deny'}`)
    // Not asserted as a bug: an operator hook is trusted code by design. The
    // assertion is only that the engine is consistent about it.
    expect(typeof d.allowed).toBe('boolean')
  }, 60_000)
})

describe('E2E liveness: a hook that never resolves', () => {
  it('records whether authorize() ever settles when beforeEvaluate hangs', async () => {
    const engine = engineWith({ beforeEvaluate: () => new Promise<never>(() => {}) })

    const settled = await Promise.race([
      engine.check('u1', 'read', DOC).then((d) => ({ done: true, value: d })),
      new Promise<{ done: false }>((r) => setTimeout(() => r({ done: false }), 3000)),
    ])

    console.info(
      `[resilience] beforeEvaluate never resolves: check() ${settled.done ? 'settled' : 'DID NOT SETTLE within 3000ms'}`,
    )
    // No hook timeout exists, so this is expected to hang. Asserted as-is so
    // the day a hook timeout lands, this test says so rather than passing
    // silently. A hang is not a fail-open, but it is an unbounded authorization
    // call with no deadline of its own.
    expect(settled.done).toBe(false)
  }, 30_000)

  it('a never-resolving afterEvaluate holds the caller after the verdict is already known', async () => {
    const engine = engineWith({ afterEvaluate: () => new Promise<never>(() => {}) })

    const settled = await Promise.race([
      engine.check('u1', 'read', DOC).then((d) => ({ done: true as const, value: d })),
      new Promise<{ done: false }>((r) => setTimeout(() => r({ done: false }), 3000)),
    ])

    console.info(
      `[resilience] afterEvaluate never resolves: check() ${settled.done ? 'settled' : 'DID NOT SETTLE within 3000ms'} (verdict was already computed)`,
    )
    expect(settled.done).toBe(false)
  }, 30_000)
})

describe('E2E fail-closed: a throwing onPolicyError alongside a broken stored policy', () => {
  it('a policy whose condition tree is corrupt denies, and the throwing hook changes nothing', async () => {
    // Write a row the evaluator cannot make sense of, straight through SQL so
    // the admin validator cannot reject it - which is exactly how a row gets
    // corrupted in production (a migration, a hand-edit, another service).
    await fixturePool.query(
      `INSERT INTO iam_policies (id, name, algorithm, rules, version)
       VALUES ('corrupt', 'corrupt', 'deny-overrides', $1::jsonb, 1)
       ON CONFLICT (id) DO UPDATE SET rules = EXCLUDED.rules`,
      [
        JSON.stringify([
          {
            actions: ['read'],
            conditions: { all: [{ field: 'subject.attributes.x', operator: 'matches', value: '(((' }] },
            effect: 'allow',
            id: 'bad',
            priority: 0,
            resources: ['doc'],
          },
        ]),
      ],
    )

    const seen: string[] = []
    const engine = engineWith({
      onPolicyError(_err, policyId) {
        seen.push(policyId)
        throw new Error('onPolicyError exploded')
      },
    })

    const d = await engine.check('u1', 'read', SECRET)
    console.info(
      `[resilience] corrupt policy + throwing onPolicyError, on a denied request: ${d.allowed ? 'ALLOW' : 'deny'}`,
    )
    expect(d.allowed, 'a corrupt policy plus a throwing onPolicyError must never allow').toBe(false)

    await fixturePool.query(`DELETE FROM iam_policies WHERE id = 'corrupt'`)
  }, 60_000)

  it('a DENY policy that becomes unparseable is dropped, and the verdict flips', async () => {
    // The sharpest partial failure there is: the backend answers, the row comes
    // back, and the engine cannot read it. If the row was the thing saying NO,
    // "drop the malformed row and carry on" is a fail-open.
    const dropped: string[] = []
    const seenByHook: string[] = []
    const engine = engineWith({
      onPolicyError(_err, policyId) {
        seenByHook.push(policyId)
      },
    })

    const denyRule = {
      actions: ['read'],
      conditions: { all: [{ field: 'subject.id', operator: 'matches', value: '^u1$' }] },
      description: 'guard',
      effect: 'deny',
      id: 'guard-rule',
      priority: 10,
      resources: ['doc'],
    }
    await fixturePool.query(
      `INSERT INTO iam_policies (id, name, algorithm, rules, version)
       VALUES ('guard', 'guard', 'deny-overrides', $1::jsonb, 1)
       ON CONFLICT (id) DO UPDATE SET rules = EXCLUDED.rules`,
      [JSON.stringify([denyRule])],
    )
    engine.cache.invalidate()
    const guarded = await engine.can('u1', 'read', DOC)
    expect(guarded, 'the guard policy must deny before it is corrupted').toBe(false)

    // Same row, same policy, one byte of the pattern broken.
    await fixturePool.query(`UPDATE iam_policies SET rules = $1::jsonb WHERE id = 'guard'`, [
      JSON.stringify([
        { ...denyRule, conditions: { all: [{ field: 'subject.id', operator: 'matches', value: '(((' }] } },
      ]),
    ])
    engine.cache.invalidate()
    const afterCorruption = await engine.can('u1', 'read', DOC)

    console.info(
      `[resilience] a DENY policy corrupted in place: verdict went deny -> ${afterCorruption ? 'ALLOW' : 'deny'}; engine onPolicyError fired ${seenByHook.length} time(s) for [${seenByHook.join(', ')}]`,
    )
    void dropped
    await fixturePool.query(`DELETE FROM iam_policies WHERE id = 'guard'`)

    expect(afterCorruption, 'an unreadable DENY policy was dropped and the request it forbade was allowed').toBe(false)
  }, 60_000)
})
