/**
 * Vitest `globalSetup` for the e2e Postgres: a preset `DUCKIAM_E2E_DATABASE_URL`, else a docker container
 * on an ephemeral port, else nothing and the e2e suites skip.
 *
 * The container is named and kept, and a run resets the schema instead of provisioning storage. Creating
 * one per run under a random name is what let 1149 abandoned data volumes reach 104GB next door in
 * duck-auth. The suite-owned containers still come and go, but they are removed with `-v`.
 *
 * WARN: two runs at once therefore share one database and reset it under each other. Point the second at
 * its own with `DUCKIAM_E2E_DATABASE_URL`.
 */
import { execFile } from 'node:child_process'
import { connect } from 'node:net'
import { join } from 'node:path'
import { promisify } from 'node:util'

const exec = promisify(execFile)

const LABEL = 'duck-iam-e2e'
const PG_IMAGE = 'postgres:18.4-alpine3.24'
const PG_CONTAINER = `${LABEL}-pg`
const PG_VOLUME = `${LABEL}-pgdata`
const KEPT = [PG_CONTAINER]
const PG_USER = 'duckiam'
const PG_PASSWORD = 'duckiam'
const PG_DB = 'duckiam_e2e'
const READY_TIMEOUT_MS = 60_000

/** Every container this run brought up, created or reused, so a half-built stack can undo itself. */
const touched: { name: string; volume: string | null }[] = []

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
 * Removes harness containers ({@link LABEL}) leaked by an earlier run that crashed, sparing the one reused.
 * WARN: keep it age-bounded; an unbounded sweep removes the Postgres a concurrent run is still using.
 */
async function removeStrays(): Promise<void> {
  await removeAgedStrays(LABEL, KEPT)
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
 * Removes containers carrying `label` created more than {@link OWNED_MAX_AGE} ago, except those in `keep`.
 * INFO: `--filter until=` is docker's own created-before filter, so no timestamp parsing is needed.
 * WARN: the reused container outlives the window by design, so age alone would collect the live one.
 */
async function removeAgedStrays(label: string, keep: string[] = []): Promise<void> {
  const listed = await docker([
    'ps',
    '-a',
    '--filter',
    `label=${label}`,
    '--filter',
    `until=${OWNED_MAX_AGE}`,
    '--format',
    '{{.Names}}',
  ]).catch(() => '')
  const names = listed.split('\n').filter((name) => name !== '' && !keep.includes(name))
  if (names.length === 0) return
  // `-v`: these died without cleanup, so their anonymous volumes have been piling up.
  await docker(['rm', '-f', '-v', ...names]).catch(() => '')
  console.info(`[e2e] removed ${names.length} abandoned test container(s) older than ${OWNED_MAX_AGE}`)
}

/** `docker inspect -f`, or null when there is no such container. */
async function inspect(name: string, format: string): Promise<string | null> {
  return docker(['inspect', '-f', format, name]).catch(() => null)
}

/**
 * The one container for a backend: created on the first run, started again on every later one.
 * WARN: a pinned image that has moved forces a rebuild, volume included. The data directory a new major
 * finds is one it refuses to read.
 */
async function reuse(name: string, image: string, volume: string | null, args: string[]): Promise<void> {
  const current = await inspect(name, '{{.Config.Image}}')
  touched.push({ name, volume })
  if (current === image) {
    if ((await inspect(name, '{{.State.Running}}')) !== 'true') await docker(['start', name])
    return
  }
  if (current !== null) {
    await docker(['rm', '-f', '-v', name]).catch(() => '')
    if (volume) await docker(['volume', 'rm', '-f', volume]).catch(() => '')
  }
  await docker(['run', '-d', '--name', name, '--label', LABEL, ...args, image])
}

/** Undoes what this run brought up, volumes included, so a backend that never came up is not reused. */
async function discard(): Promise<void> {
  for (const { name, volume } of touched.splice(0, touched.length)) {
    await docker(['rm', '-f', '-v', name]).catch(() => '')
    if (volume) await docker(['volume', 'rm', '-f', volume]).catch(() => '')
  }
}

function psql(args: string[]): Promise<string> {
  return docker(['exec', PG_CONTAINER, 'psql', '-U', PG_USER, '-d', PG_DB, '-v', 'ON_ERROR_STOP=1', ...args])
}

async function startPostgres(): Promise<string> {
  await reuse(PG_CONTAINER, PG_IMAGE, PG_VOLUME, [
    '-p',
    '0:5432',
    // Postgres 18 declares `/var/lib/postgresql`. Mounting the `data` under it crash-loops.
    '-v',
    `${PG_VOLUME}:/var/lib/postgresql`,
    '-e',
    `POSTGRES_USER=${PG_USER}`,
    '-e',
    `POSTGRES_PASSWORD=${PG_PASSWORD}`,
    '-e',
    `POSTGRES_DB=${PG_DB}`,
  ])
  await waitUntilReady(PG_CONTAINER, ['pg_isready', '-U', PG_USER, '-d', PG_DB])
  // `pg_isready` goes true once during init, before the server restarts; prove a query round-trips first.
  await waitUntilReady(PG_CONTAINER, ['psql', '-U', PG_USER, '-d', PG_DB, '-c', 'SELECT 1'])
  // The schema file only creates, and a reused database already holds the tables. Dropping the schema
  // is what stands in for provisioning a new one.
  await psql(['-c', 'DROP SCHEMA public CASCADE; CREATE SCHEMA public'])
  // Seed the schema once for every suite. Copied in, not piped, because `execFile` has no stdin.
  await docker(['cp', join(import.meta.dirname, 'pg-e2e-schema.sql'), `${PG_CONTAINER}:/tmp/schema.sql`])
  await psql(['-f', '/tmp/schema.sql'])
  const port = await publishedPort(PG_CONTAINER, 5432)
  await waitUntilReachable(port)
  return `postgres://${PG_USER}:${PG_PASSWORD}@127.0.0.1:${port}/${PG_DB}`
}

/**
 * Vitest `globalSetup`: brings the e2e Postgres up once and publishes it as `DUCKIAM_E2E_DATABASE_URL`.
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
    // A half-built stack is worse than none, and one that never came up must not be what the next run
    // reuses: undo this run's containers and let the suites skip.
    await discard()
    delete process.env.DUCKIAM_E2E_DATABASE_URL
    console.info(`[e2e] container setup failed, suites will skip: ${err instanceof Error ? err.message : err}`)
  }
}
