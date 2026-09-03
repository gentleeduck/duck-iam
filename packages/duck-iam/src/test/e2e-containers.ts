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

/**
 * How long the availability probe may take. `docker info` does not return when
 * the CLI is installed and the daemon socket exists but nothing is listening -
 * a stopped Docker Desktop, which is the ordinary state on a machine that is
 * not running e2e tests. `execFile` has no timeout by default, so that hung
 * `globalSetup`, and with it *every* vitest invocation in the package,
 * including Stryker's dry run.
 *
 * Was `5_000`, which is inside the range `docker info` takes on a loaded
 * machine: on macOS it costs ~2.5s idle, and the whole E2E sweep - eighteen
 * suites, several of them starting containers - is exactly the load that pushes
 * it past five seconds. A slow probe then read as "no docker" and every suite
 * skipped itself, so the run reported green having tested nothing. A probe that
 * decides whether 650 tests run must not be tuned so close to the thing it
 * measures.
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

/**
 * Set `DUCKIAM_E2E_REQUIRE_DOCKER=1` to turn "docker is not available" from a
 * silent skip into a failure.
 *
 * The skip exists so a contributor without docker can still run the package's
 * suite, and it is right for that. It is wrong for a run whose *purpose* is the
 * E2E suites: those skip themselves file by file, so the run reports green and
 * the only trace is one `console.info` line scrolled off the top. Anyone
 * deliberately exercising the E2E suites should set this.
 */
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
  await docker(['rm', '-f', '-v', ...ids.split('\n')])
}

/**
 * The label every *suite-owned* container carries, and the age past which one
 * is certainly abandoned.
 *
 * The containers a suite starts for itself deliberately do NOT carry
 * {@link LABEL}: `removeStrays` deletes every container with that label at the
 * start of *any* vitest invocation, which would pull the server out from under
 * a suite still using it. The cost of staying unlabelled was that nothing ever
 * collected them - an interrupted run (Ctrl-C, a timeout, a crash before
 * `afterAll`) left them running forever, and four such orphans, two to four
 * hours old, were once found throttling the daemon badly enough to turn a
 * 30-second suite into a 205-second one.
 *
 * A second label plus an age bound gets both: these are swept, but only when
 * they are far too old to belong to a run in progress. Suites finish in
 * minutes, so an hour is not a race - it is a container nobody is coming back
 * for.
 */
export const OWNED_LABEL = 'duck-iam-e2e-owned'
const OWNED_MAX_AGE = '60m'

/**
 * Remove suite-owned containers old enough that no live run can own them.
 *
 * `--filter until=` is docker's own "created before" predicate, so this never
 * has to parse a timestamp, and a container started by a concurrent run is far
 * too young to match.
 */
async function removeAgedOwnedStrays(): Promise<void> {
  const ids = await docker([
    'ps',
    '-aq',
    '--filter',
    `label=${OWNED_LABEL}`,
    '--filter',
    `until=${OWNED_MAX_AGE}`,
  ]).catch(() => '')
  if (ids.length === 0) return
  const names = ids.split('\n').filter(Boolean)
  // `-v` matters more here than anywhere: these are the containers that died
  // without running their own cleanup, so their anonymous volumes are the ones
  // that have been accumulating.
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

/**
 * Vitest `globalSetup`: bring up the Postgres the e2e suites need, once for the
 * whole run, and publish its URL through `DUCKIAM_E2E_DATABASE_URL`.
 *
 * Defers to an already-set URL, so `.env.test` and real CI service containers
 * win over anything *started* here - but the aged-stray sweep still runs, since
 * suites that own their own backends leak them either way. Absent docker is not a failure - the suites
 * read the same variable and skip themselves - except under
 * `DUCKIAM_E2E_REQUIRE_DOCKER`, which exists so CI cannot pass by silently
 * skipping every e2e file. A setup that fails halfway tears itself down and
 * unsets the variable rather than leaving suites pointed at a half-built stack.
 */
export async function setup(): Promise<void> {
  const hasDocker = await dockerAvailable()

  // Above the early return below, not after it. Suites that own their own
  // backends - the redis invalidation e2e starts both a Redis and a Postgres of
  // its own - label them `OWNED_LABEL` and start them whether or not this setup
  // started anything. Left below the return, the sweep never ran at all for
  // anyone with `DUCKIAM_E2E_DATABASE_URL` in `.env.test`, which is the normal
  // local setup, so their crashed runs accumulated containers (and the
  // anonymous volumes behind them) indefinitely.
  //
  // Safe to hoist precisely because it is age-bounded: everything it collects
  // is older than `OWNED_MAX_AGE` and so cannot belong to a run in progress.
  // The cost is one docker probe on a path that used to skip it.
  if (hasDocker) await removeAgedOwnedStrays()

  // `.env.test` and real CI service containers both win: if the caller already
  // pointed us somewhere, do not start anything.
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
 * Vitest `globalTeardown`: remove every container this run started.
 *
 * `-v` as well as `-f`, or the anonymous volume behind each container outlives
 * it and the disk fills one run at a time. Failures are logged rather than
 * thrown - throwing here would fail an otherwise green run, and the aged-stray
 * sweep in {@link setup} collects whatever is left behind.
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
