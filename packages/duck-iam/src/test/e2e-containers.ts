/**
 * Vitest `globalSetup`: bring up the Postgres the e2e suites need, then take it
 * away again.
 *
 * Without this, e2e coverage would depend on a developer hand-provisioning a
 * database and cloning a schema into it - which is the same as not having the
 * suites at all.
 *
 * Order of preference:
 *   1. `DUCKIAM_E2E_DATABASE_URL` already set (your own infra, or CI services).
 *   2. Docker available - a throwaway container on an ephemeral port, removed on exit.
 *   3. Neither - the variable stays unset and every e2e suite skips itself.
 *
 * The container publishes to port 0 so the host picks a free port; nothing can
 * collide with a dev stack already sitting on 5432.
 */
import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { connect } from 'node:net'
import { join } from 'node:path'
import { promisify } from 'node:util'

const exec = promisify(execFile)

const LABEL = 'duck-iam-e2e'
const PG_IMAGE = 'postgres:16-alpine'
const PG_USER = 'duckiam'
const PG_PASSWORD = 'duckiam'
const PG_DB = 'duckiam_e2e'
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

/** Poll `probe` until it succeeds. A container is up long before it accepts traffic. */
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
 * forwarding is accepting yet, and a suite connecting in that gap gets ECONNREFUSED.
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

/** Remove any container this harness leaked in an earlier run that died badly. */
async function removeStrays(): Promise<void> {
  const ids = await docker(['ps', '-aq', '--filter', `label=${LABEL}`])
  if (ids.length === 0) return
  await docker(['rm', '-f', ...ids.split('\n')])
}

async function startPostgres(): Promise<string> {
  const name = `${LABEL}-pg-${randomBytes(4).toString('hex')}`
  await docker([
    'run',
    '-d',
    '--name',
    name,
    '--label',
    LABEL,
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
  started.push(name)
  await waitUntilReady(name, ['pg_isready', '-U', PG_USER, '-d', PG_DB])
  // `pg_isready` goes true once during init, before the init scripts finish and
  // the server restarts for real connections. Prove a query round-trips before
  // handing the URL out, or the first suite races the bootstrap.
  await waitUntilReady(name, ['psql', '-U', PG_USER, '-d', PG_DB, '-c', 'SELECT 1'])
  // Seed the schema once here, so no suite pays for it. Copied in rather than
  // piped: `execFile` has no stdin.
  await docker(['cp', join(import.meta.dirname, 'pg-e2e-schema.sql'), `${name}:/tmp/schema.sql`])
  await docker(['exec', name, 'psql', '-U', PG_USER, '-d', PG_DB, '-v', 'ON_ERROR_STOP=1', '-f', '/tmp/schema.sql'])
  const port = await publishedPort(name, 5432)
  await waitUntilReachable(port)
  return `postgres://${PG_USER}:${PG_PASSWORD}@127.0.0.1:${port}/${PG_DB}`
}

export async function setup(): Promise<void> {
  // `.env.test` and real CI service containers both win: if the caller already
  // pointed us somewhere, do not start anything.
  if (process.env.DUCKIAM_E2E_DATABASE_URL) return

  if (!(await dockerAvailable())) {
    console.info('[e2e] docker unavailable; e2e suites will skip themselves')
    return
  }

  await removeStrays()
  try {
    process.env.DUCKIAM_E2E_DATABASE_URL = await startPostgres()
  } catch (err) {
    // A half-built stack is worse than none: tear down and let the suites skip.
    await teardown()
    delete process.env.DUCKIAM_E2E_DATABASE_URL
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
