/**
 * Vitest `globalSetup`: bring up the infrastructure the e2e suites need, then take
 * it away again.
 *
 * Before this existed, e2e coverage depended on a developer having hand-provisioned
 * Redis and a Postgres database whose schema was cloned out of another repo. That
 * made the suites unrunnable anywhere else, which is the same as not having them.
 *
 * Order of preference:
 *   1. `DUCKAUTH_E2E_*` already set (your own infra, or CI services) - used as-is.
 *   2. Docker available - throwaway containers on ephemeral ports, removed on exit.
 *   3. Neither - the variables stay unset and every e2e suite skips itself.
 *
 * Containers publish to port 0 so the host picks a free port; nothing can collide
 * with a dev stack already sitting on 6379 or 5432.
 */
import { execFile } from 'node:child_process'
import { connect } from 'node:net'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { randomToken } from '~/core/crypto'

const exec = promisify(execFile)

const LABEL = 'duck-auth-e2e'
const REDIS_IMAGE = 'redis:7-alpine'
const PG_IMAGE = 'postgres:16-alpine'
const MYSQL_IMAGE = 'mysql:8'
const MYSQL_DB = 'duckauth_e2e'
const MYSQL_ROOT_PASSWORD = 'duckauth'
const PG_USER = 'duckauth'
const PG_PASSWORD = 'duckauth'
const PG_DB = 'duckauth_e2e'
const READY_TIMEOUT_MS = 60_000

const started: string[] = []

async function docker(args: string[]): Promise<string> {
  const { stdout } = await exec('docker', args, { encoding: 'utf8' })
  return stdout.trim()
}

async function dockerAvailable(): Promise<boolean> {
  try {
    await docker(['info', '--format', '{{.ServerVersion}}'])
    return true
  } catch {
    return false
  }
}

/** Host port docker assigned to `containerPort` when published to `0`. */
async function publishedPort(name: string, containerPort: number): Promise<number> {
  const raw = await docker(['port', name, String(containerPort)])
  // `0.0.0.0:49154` or `[::]:49154`, one line per address family.
  const port = raw.split('\n')[0]?.split(':').pop()
  const parsed = Number(port)
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`could not read published port for ${name}: ${JSON.stringify(raw)}`)
  }
  return parsed
}

/** Poll `probe` until it succeeds. Containers are up long before they accept traffic. */
async function waitUntilReady(name: string, probe: string[]): Promise<void> {
  const deadline = Date.now() + READY_TIMEOUT_MS
  let lastError = ''
  while (Date.now() < deadline) {
    try {
      await docker(['exec', name, ...probe])
      return
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err)
      await new Promise((r) => setTimeout(r, 250))
    }
  }
  throw new Error(`${name} was not ready within ${READY_TIMEOUT_MS}ms: ${lastError}`)
}

/**
 * Wait until the published port accepts a TCP connection from the host. The
 * in-container probes prove the server is up; they do not prove docker's port
 * forwarding is accepting yet, and a suite that connects in that gap gets
 * ECONNREFUSED.
 */
async function waitUntilReachable(port: number): Promise<void> {
  const deadline = Date.now() + READY_TIMEOUT_MS
  let lastError = ''
  while (Date.now() < deadline) {
    const ok = await new Promise<boolean>((resolve) => {
      const socket = connect({ host: '127.0.0.1', port })
      const done = (result: boolean) => {
        socket.destroy()
        resolve(result)
      }
      socket.once('connect', () => done(true))
      socket.once('error', (err) => {
        lastError = err.message
        done(false)
      })
      socket.setTimeout(1000, () => done(false))
    })
    if (ok) return
    await new Promise((r) => setTimeout(r, 100))
  }
  throw new Error(`127.0.0.1:${port} never accepted a connection: ${lastError}`)
}

async function run(name: string, args: string[]): Promise<void> {
  await docker(['run', '-d', '--name', name, '--label', LABEL, ...args])
  started.push(name)
}

/** Remove any container this harness leaked in an earlier run that died badly. */
async function removeStrays(): Promise<void> {
  const ids = await docker(['ps', '-aq', '--filter', `label=${LABEL}`])
  if (ids.length === 0) return
  await docker(['rm', '-f', ...ids.split('\n')])
}

async function startRedis(): Promise<string> {
  const name = `${LABEL}-redis-${randomToken(4)}`
  await run(name, ['-p', '0:6379', REDIS_IMAGE])
  await waitUntilReady(name, ['redis-cli', 'ping'])
  const port = await publishedPort(name, 6379)
  await waitUntilReachable(port)
  return `redis://127.0.0.1:${port}`
}

async function startPostgres(): Promise<string> {
  const name = `${LABEL}-pg-${randomToken(4)}`
  await run(name, [
    '-p',
    '0:5432',
    '-e',
    `POSTGRES_USER=${PG_USER}`,
    '-e',
    `POSTGRES_PASSWORD=${PG_PASSWORD}`,
    '-e',
    `POSTGRES_DB=${PG_DB}`,
    PG_IMAGE,
  ])
  await waitUntilReady(name, ['pg_isready', '-U', PG_USER, '-d', PG_DB])
  // `pg_isready` goes true once during init, before the init scripts finish and the
  // server restarts for real connections. Prove a query round-trips before handing
  // the URL out, or the first suite races the bootstrap.
  await waitUntilReady(name, ['psql', '-U', PG_USER, '-d', PG_DB, '-c', 'SELECT 1'])
  // Seed the shipped schema once here, so no suite pays for it and every suite can
  // assume the tables exist. Copied in rather than piped: `execFile` has no stdin.
  await docker(['cp', join(import.meta.dirname, 'pg-e2e-schema.sql'), `${name}:/tmp/schema.sql`])
  await docker(['exec', name, 'psql', '-U', PG_USER, '-d', PG_DB, '-v', 'ON_ERROR_STOP=1', '-f', '/tmp/schema.sql'])
  const port = await publishedPort(name, 5432)
  await waitUntilReachable(port)
  return `postgres://${PG_USER}:${PG_PASSWORD}@127.0.0.1:${port}/${PG_DB}`
}

async function startMysql(): Promise<string> {
  const name = `${LABEL}-mysql-${randomToken(4)}`
  await run(name, [
    '-p',
    '0:3306',
    '-e',
    `MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD}`,
    '-e',
    `MYSQL_DATABASE=${MYSQL_DB}`,
    MYSQL_IMAGE,
  ])
  // mysqladmin reports ready during init too, so prove a query round-trips.
  await waitUntilReady(name, ['mysqladmin', 'ping', '-h', '127.0.0.1', `-p${MYSQL_ROOT_PASSWORD}`])
  await waitUntilReady(name, ['mysql', `-uroot`, `-p${MYSQL_ROOT_PASSWORD}`, MYSQL_DB, '-e', 'SELECT 1'])
  await docker(['cp', join(import.meta.dirname, 'mysql-e2e-schema.sql'), `${name}:/tmp/schema.sql`])
  await docker([
    'exec',
    name,
    'sh',
    '-c',
    `mysql -uroot -p${MYSQL_ROOT_PASSWORD} ${MYSQL_DB} < /tmp/schema.sql`,
  ])
  const port = await publishedPort(name, 3306)
  await waitUntilReachable(port)
  return `mysql://root:${MYSQL_ROOT_PASSWORD}@127.0.0.1:${port}/${MYSQL_DB}`
}

export async function setup(): Promise<void> {
  // `.env.test` (loaded by e2e-env) and real CI service containers both win: if the
  // caller already pointed us somewhere, do not start anything.
  const haveRedis = Boolean(process.env.DUCKAUTH_E2E_REDIS_URL)
  const havePg = Boolean(process.env.DUCKAUTH_E2E_DATABASE_URL)
  const haveMysql = Boolean(process.env.DUCKAUTH_E2E_MYSQL_URL)
  if (haveRedis && havePg && haveMysql) return

  if (!(await dockerAvailable())) {
    console.info('[e2e] docker unavailable; e2e suites will skip themselves')
    return
  }

  await removeStrays()
  try {
    if (!haveRedis) process.env.DUCKAUTH_E2E_REDIS_URL = await startRedis()
    if (!havePg) process.env.DUCKAUTH_E2E_DATABASE_URL = await startPostgres()
    if (!haveMysql) process.env.DUCKAUTH_E2E_MYSQL_URL = await startMysql()
  } catch (err) {
    // A half-built stack is worse than none: tear down and let the suites skip.
    await teardown()
    delete process.env.DUCKAUTH_E2E_REDIS_URL
    delete process.env.DUCKAUTH_E2E_DATABASE_URL
    delete process.env.DUCKAUTH_E2E_MYSQL_URL
    console.info(`[e2e] container setup failed, suites will skip: ${err instanceof Error ? err.message : err}`)
  }
}

export async function teardown(): Promise<void> {
  if (started.length === 0) return
  const names = started.splice(0, started.length)
  try {
    await docker(['rm', '-f', ...names])
  } catch (err) {
    // Surface it: a silent failure here leaks containers until the next sweep.
    console.warn(`[e2e] could not remove ${names.join(', ')}: ${err instanceof Error ? err.message : err}`)
  }
}
