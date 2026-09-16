/**
 * Vitest `globalSetup` for the e2e Postgres: a preset `DUCKIAM_E2E_DATABASE_URL`, else a throwaway docker container
 * on an ephemeral port, else nothing and the e2e suites skip.
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

/**
 * Timeout for `docker info`, which hangs when the daemon socket exists but nothing listens (a stopped Docker Desktop).
 * WARN: keep it generous; a loaded machine takes over 5s, and a slow probe reads as "no docker" and skips every suite.
 */
const DOCKER_PROBE_TIMEOUT_MS = 30_000

async function docker(args: string[], timeout?: number): Promise<string> {
  const { stdout } = await exec('docker', args, { encoding: 'utf8', timeout })
  return stdout.trim()
}

async function dockerAvailable(): Promise<boolean> {
  try {
    await docker(['info', '--format', '{{.ServerVersion}}'], DOCKER_PROBE_TIMEOUT_MS)
    return true
  } catch {
    return false
  }
}

/** `DUCKIAM_E2E_REQUIRE_DOCKER=1` makes missing docker a failure instead of a silent skip; set it on e2e runs. */
function dockerIsRequired(): boolean {
  const flag = process.env.DUCKIAM_E2E_REQUIRE_DOCKER
  return flag !== undefined && flag !== '' && flag !== '0' && flag !== 'false'
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
 * Waits until the published port accepts a TCP connection from the host.
 * INFO: in-container probes do not prove docker's port forwarding is up; connecting in that gap gets ECONNREFUSED.
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

/**
 * Removes harness containers ({@link LABEL}) leaked by an earlier run that crashed.
 * WARN: keep it age-bounded; an unbounded sweep removes the Postgres a concurrent run is still using.
 */
async function removeStrays(): Promise<void> {
  await removeAgedStrays(LABEL)
}

/**
 * Label on containers a suite starts for itself, and the age past which one is certainly abandoned.
 * NOTE: suites finish in minutes, so an hour-old container cannot belong to a live run.
 */
export const OWNED_LABEL = 'duck-iam-e2e-owned'
const OWNED_MAX_AGE = '60m'

/** Removes suite-owned containers old enough that no live run can own them. */
async function removeAgedOwnedStrays(): Promise<void> {
  await removeAgedStrays(OWNED_LABEL)
}

/**
 * Removes containers carrying `label` created more than {@link OWNED_MAX_AGE} ago.
 * INFO: `--filter until=` is docker's own created-before filter, so no timestamp parsing is needed.
 */
async function removeAgedStrays(label: string): Promise<void> {
  const ids = await docker([
    'ps',
    '-aq',
    '--filter',
    `label=${label}`,
    '--filter',
    `until=${OWNED_MAX_AGE}`,
  ]).catch(() => '')
  if (ids.length === 0) return
  const names = ids.split('\n').filter(Boolean)
  // `-v`: these died without cleanup, so their anonymous volumes have been piling up.
  await docker(['rm', '-f', '-v', ...names]).catch(() => '')
  console.info(`[e2e] removed ${names.length} abandoned test container(s) older than ${OWNED_MAX_AGE}`)
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
  // `pg_isready` goes true once during init, before the server restarts; prove a query round-trips first.
  await waitUntilReady(name, ['psql', '-U', PG_USER, '-d', PG_DB, '-c', 'SELECT 1'])
  // Seed the schema once for every suite. Copied in, not piped, because `execFile` has no stdin.
  await docker(['cp', join(import.meta.dirname, 'pg-e2e-schema.sql'), `${name}:/tmp/schema.sql`])
  await docker(['exec', name, 'psql', '-U', PG_USER, '-d', PG_DB, '-v', 'ON_ERROR_STOP=1', '-f', '/tmp/schema.sql'])
  const port = await publishedPort(name, 5432)
  await waitUntilReachable(port)
  return `postgres://${PG_USER}:${PG_PASSWORD}@127.0.0.1:${port}/${PG_DB}`
}

/**
 * Vitest `globalSetup`: starts the e2e Postgres once and publishes it as `DUCKIAM_E2E_DATABASE_URL`.
 * A preset URL wins; missing docker skips unless `DUCKIAM_E2E_REQUIRE_DOCKER` is set. A failed start tears down.
 */
export async function setup(): Promise<void> {
  const hasDocker = await dockerAvailable()

  // NOTE: sweep before the preset-URL return; suites that own their backends leak them either way.
  // Safe because the sweep is age-bounded.
  if (hasDocker) await removeAgedOwnedStrays()

  // A preset URL (`.env.test` or CI services) means start nothing.
  if (process.env.DUCKIAM_E2E_DATABASE_URL) return

  if (!hasDocker) {
    if (dockerIsRequired()) {
      throw new Error(
        '[e2e] DUCKIAM_E2E_REQUIRE_DOCKER is set but docker did not answer within ' +
          `${DOCKER_PROBE_TIMEOUT_MS}ms. Refusing to run the suite with every e2e file silently skipped.`,
      )
    }
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

/**
 * Vitest `globalTeardown`: removes this run's containers with `-v`, so their anonymous volumes go too.
 * Logs rather than throws, so a green run stays green; the aged-stray sweep in {@link setup} collects leftovers.
 */
export async function teardown(): Promise<void> {
  if (started.length === 0) return
  const names = started.splice(0, started.length)
  try {
    await docker(['rm', '-f', '-v', ...names])
  } catch (err) {
    // Surface it: a silent failure here leaks containers until the next sweep.
    console.warn(`[e2e] could not remove ${names.join(', ')}: ${err instanceof Error ? err.message : err}`)
  }
}
