/**
 * Vitest `globalSetup`: bring up what the e2e suites need and leave it up for the next run. In order of
 * preference, `DUCKAUTH_E2E_*` already set is used as-is; failing that docker gets one container per backend,
 * reused after the first run; failing that the variables stay unset and every e2e suite skips itself.
 *
 * WARN: a skip is silent, so on a machine with no docker `bun run test:e2e` exits 0 having proved nothing about
 * pg, mysql or valkey, the three backends with no in-process substitute. `DUCKAUTH_E2E_REQUIRE=1` makes that a
 * failure, and CI sets it. Only an absent docker skips: if docker answers and setup then fails, the prerequisite
 * is present and broken, which is how a bad `ALTER` once left all 693 tests skipped behind a green exit code.
 *
 * WARN: two runs at once share the one database and reset it under each other. Point the second at its own
 * backends with `DUCKAUTH_E2E_*`.
 */
import { execFile } from 'node:child_process'
import { connect } from 'node:net'
import { join } from 'node:path'
import { promisify } from 'node:util'

const exec = promisify(execFile)

const LABEL = 'duck-auth-e2e'
const VALKEY_IMAGE = 'valkey/valkey:9-alpine'
const PG_IMAGE = 'postgres:18.4-alpine3.24'
const MYSQL_IMAGE = 'mysql:8.4'
const VALKEY_CONTAINER = `${LABEL}-valkey`
const PG_CONTAINER = `${LABEL}-pg`
const MYSQL_CONTAINER = `${LABEL}-mysql`
const PG_VOLUME = `${LABEL}-pgdata`
const MYSQL_VOLUME = `${LABEL}-mysqldata`
const KEPT = [VALKEY_CONTAINER, PG_CONTAINER, MYSQL_CONTAINER]
const MYSQL_DB = 'duckauth_e2e'
const MYSQL_ROOT_PASSWORD = 'duckauth'
const PG_USER = 'duckauth'
const PG_PASSWORD = 'duckauth'
const PG_DB = 'duckauth_e2e'
const READY_TIMEOUT_MS = 60_000

/** Every container this run brought up, created or reused, so a half-built stack can undo itself. */
const touched: { name: string; volume: string | null }[] = []

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

/** Wait until the published port accepts a TCP connection from the host. The in-container probes prove the
 *  server is up, not that docker's port forwarding is, and a suite connecting in that gap gets ECONNREFUSED. */
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

/** `docker inspect -f`, or null when there is no such container. */
async function inspect(name: string, format: string): Promise<string | null> {
  return docker(['inspect', '-f', format, name]).catch(() => null)
}

/** The one container for a backend, created on the first run and started again on every later one. A pinned
 *  image that has moved forces a rebuild, volume included, because a new major refuses the old data dir. */
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

/**
 * Removes any random-named container left under the label. The three this harness keeps are named,
 * so anything else belongs to a run that is over.
 */
async function removeStrays(): Promise<void> {
  const listed = await docker(['ps', '-a', '--filter', `label=${LABEL}`, '--format', '{{.Names}}']).catch(() => '')
  const strays = listed.split('\n').filter((name) => name !== '' && !KEPT.includes(name))
  if (strays.length === 0) return
  // `-v`: they were removed without it, which is what left a volume behind for every one of them.
  await docker(['rm', '-f', '-v', ...strays]).catch(() => '')
}

/** Undo what this run brought up, volumes included, so a backend that never came up is not reused. */
async function discard(): Promise<void> {
  for (const { name, volume } of touched.splice(0, touched.length)) {
    await docker(['rm', '-f', '-v', name]).catch(() => '')
    if (volume) await docker(['volume', 'rm', '-f', volume]).catch(() => '')
  }
}

async function startValkey(): Promise<string> {
  // No volume: the image declares none, and the limiter and nonce stores hold nothing worth a restart.
  await reuse(VALKEY_CONTAINER, VALKEY_IMAGE, null, ['-p', '0:6379'])
  await waitUntilReady(VALKEY_CONTAINER, ['valkey-cli', 'ping'])
  // Reused, so the keys the run before wrote are still in it.
  await docker(['exec', VALKEY_CONTAINER, 'valkey-cli', 'flushall'])
  const port = await publishedPort(VALKEY_CONTAINER, 6379)
  await waitUntilReachable(port)
  return `redis://127.0.0.1:${port}`
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
  // `pg_isready` goes true once during init, before the init scripts finish and the
  // server restarts for real connections. Prove a query round-trips before handing
  // the URL out, or the first suite races the bootstrap.
  await waitUntilReady(PG_CONTAINER, ['psql', '-U', PG_USER, '-d', PG_DB, '-c', 'SELECT 1'])
  // The schema file only knows how to create, and on a reused database the tables are already
  // there. Dropping the schema is what stands in for provisioning a new one.
  await psql(['-c', 'DROP SCHEMA public CASCADE; CREATE SCHEMA public'])
  // Copied in rather than piped: `execFile` has no stdin.
  await docker(['cp', join(import.meta.dirname, 'pg-e2e-schema.sql'), `${PG_CONTAINER}:/tmp/schema.sql`])
  await psql(['-f', '/tmp/schema.sql'])
  const port = await publishedPort(PG_CONTAINER, 5432)
  await waitUntilReachable(port)
  return `postgres://${PG_USER}:${PG_PASSWORD}@127.0.0.1:${port}/${PG_DB}`
}

async function startMysql(): Promise<string> {
  await reuse(MYSQL_CONTAINER, MYSQL_IMAGE, MYSQL_VOLUME, [
    '-p',
    '0:3306',
    '-v',
    `${MYSQL_VOLUME}:/var/lib/mysql`,
    '-e',
    `MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD}`,
    '-e',
    `MYSQL_DATABASE=${MYSQL_DB}`,
  ])
  // mysqladmin reports ready during init too, so prove a query round-trips.
  await waitUntilReady(MYSQL_CONTAINER, ['mysqladmin', 'ping', '-h', '127.0.0.1', `-p${MYSQL_ROOT_PASSWORD}`])
  await waitUntilReady(MYSQL_CONTAINER, ['mysql', `-uroot`, `-p${MYSQL_ROOT_PASSWORD}`, MYSQL_DB, '-e', 'SELECT 1'])
  // Same as dropping the pg schema: the file creates, so the database it creates into must be empty.
  await docker([
    'exec',
    MYSQL_CONTAINER,
    'mysql',
    `-uroot`,
    `-p${MYSQL_ROOT_PASSWORD}`,
    '-e',
    `DROP DATABASE IF EXISTS \`${MYSQL_DB}\`; CREATE DATABASE \`${MYSQL_DB}\``,
  ])
  await docker(['cp', join(import.meta.dirname, 'mysql-e2e-schema.sql'), `${MYSQL_CONTAINER}:/tmp/schema.sql`])
  await docker([
    'exec',
    MYSQL_CONTAINER,
    'sh',
    '-c',
    `mysql -uroot -p${MYSQL_ROOT_PASSWORD} ${MYSQL_DB} < /tmp/schema.sql`,
  ])
  const port = await publishedPort(MYSQL_CONTAINER, 3306)
  await waitUntilReachable(port)
  return `mysql://root:${MYSQL_ROOT_PASSWORD}@127.0.0.1:${port}/${MYSQL_DB}`
}

export async function setup(): Promise<void> {
  // `.env.test` (loaded by e2e-env) and real CI service containers both win: if the
  // caller already pointed this somewhere, do not start anything.
  const haveRedis = Boolean(process.env.DUCKAUTH_E2E_REDIS_URL)
  const havePg = Boolean(process.env.DUCKAUTH_E2E_DATABASE_URL)
  const haveMysql = Boolean(process.env.DUCKAUTH_E2E_MYSQL_URL)
  const required = process.env.DUCKAUTH_E2E_REQUIRE === '1'
  if (haveRedis && havePg && haveMysql) return

  if (!(await dockerAvailable())) {
    if (required) throw new Error('[e2e] DUCKAUTH_E2E_REQUIRE=1 but docker is unavailable and no DUCKAUTH_E2E_* url is set')
    console.info('[e2e] docker unavailable; e2e suites will skip themselves')
    return
  }

  await removeStrays()
  try {
    if (!haveRedis) process.env.DUCKAUTH_E2E_REDIS_URL = await startValkey()
    if (!havePg) process.env.DUCKAUTH_E2E_DATABASE_URL = await startPostgres()
    if (!haveMysql) process.env.DUCKAUTH_E2E_MYSQL_URL = await startMysql()
  } catch (err) {
    // A half-built stack is worse than none, and one that never came up must not be what the next
    // run reuses: undo this run's containers before failing.
    await discard()
    delete process.env.DUCKAUTH_E2E_REDIS_URL
    delete process.env.DUCKAUTH_E2E_DATABASE_URL
    delete process.env.DUCKAUTH_E2E_MYSQL_URL
    throw new Error(
      `[e2e] docker is up but the backends could not be provisioned, so the suites would skip a tier that is expected to run: ${err instanceof Error ? err.message : err}`,
      { cause: err },
    )
  }
}
