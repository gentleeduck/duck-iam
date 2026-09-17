#!/usr/bin/env node
/**
 * What a store call costs on every adapter, measured the same way on each.
 *
 * Usage: bun run bench:adapters [memory|sqlite|pg|mysql]   (default: all)
 *
 * Each backend is seeded with the same 50k identities and 100k logins, then every call is timed at the
 * adapter boundary - drizzle building the SQL, the driver, the round trip and the row mapping all
 * included, because that is what a caller waits for. pg and mysql run in containers this script starts
 * and removes; sqlite gets a temp file; memory is seeded through `raw`, since `create` checks the
 * address and every login against every row it holds and seeding through it is quadratic.
 *
 * The numbers this produced are recorded in src/adapters/README.md, with the host they came off.
 */

import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import { createRequire } from 'node:module'
import os from 'node:os'
import path from 'node:path'
import { DrizzleMysqlAdapter } from '../src/adapters/drizzle/mysql'
import { DrizzlePgAdapter } from '../src/adapters/drizzle/pg'
import { DrizzleSqliteAdapter } from '../src/adapters/drizzle/sqlite'
import { MemoryAdapter } from '../src/adapters/memory'
import type { Adapter } from '../src/adapters/adapter'
import type { Credential } from '../src/core/credentials'
import { credentialInput, sessionInput } from '../src/test/store-inputs'

const N = Number(process.env.BENCH_ROWS ?? 50_000)
const READS = 300
const WRITES = 200
const WARM = 30
/** The seed leaves dirty buffers and a checkpoint behind; reads taken on top of that measure the seed. */
const SETTLE_MS = 8_000
const SCHEMA = path.join(import.meta.dirname, '..', 'src', 'test')

// Captured, not inherited: the readiness loop is expected to fail until the server is up, and a
// container that was never there is not an error worth printing.
const sh = (cmd: string, args: string[], stdin?: string) =>
  execFileSync(cmd, args, { encoding: 'utf8', input: stdin, maxBuffer: 1 << 28, stdio: ['pipe', 'pipe', 'pipe'] })
const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
const pct = (xs: number[], p: number) => xs.slice().sort((a, b) => a - b)[Math.floor(xs.length * p)] ?? 0
const fmt = (ms: number) => (ms < 0.01 ? `${(ms * 1000).toFixed(0)} µs` : `${ms.toFixed(3)} ms`)

let n = 0
const input = () => {
  const tag = `bench-${Date.now().toString(36)}-${n++}`
  return {
    emailVerified: false,
    profile: { email: `${tag}@example.com`, username: tag },
    providers: [
      { addedAt: new Date(), providerId: 'google', providerSub: `g-${tag}` },
      { addedAt: new Date(), providerId: 'github', providerSub: `h-${tag}` },
    ],
    version: 1,
  }
}

async function time(call: (i: number) => Promise<unknown>, runs: number) {
  for (let i = 0; i < WARM; i++) await call(-1 - i)
  const xs: number[] = []
  for (let i = 0; i < runs; i++) {
    const started = performance.now()
    await call(i)
    xs.push(performance.now() - started)
  }

  return { p50: pct(xs, 0.5), p95: pct(xs, 0.95) }
}

type Stat = { p50: number; p95: number }

/** Rows for every store call, in one pass over an adapter that is already seeded. */
async function report(label: string, adapter: Adapter.Me) {
  const { credentials, events, identities, sessions } = adapter
  const ctx = {}
  const out: [string, Stat][] = []
  const add = async (name: string, call: (i: number) => Promise<unknown>, runs = READS) =>
    out.push([name, await time(call, runs)])

  // Through the store itself, so no backend needs its own sampling query.
  const sample: { email: string; id: string; sub: string }[] = []
  for (let i = 1; sample.length < 500; i++) {
    const email = `user${i}@example.com`
    const row = await identities.find({ email })
    const google = row?.providers.find((link) => link.providerId === 'google')
    if (row && google) sample.push({ email, id: row.id, sub: google.providerSub })
  }
  const pick = (i: number) => sample[((i % sample.length) + sample.length) % sample.length] ?? sample[0]

  /** A pool big enough for the warm-ups and the timed runs, since these calls consume what they touch. */
  const pool = async (count = WRITES + WARM) => {
    const ids: string[] = []
    for (let i = 0; i < count; i++) ids.push((await identities.create(input())).id)

    return ids
  }
  const each = (ids: string[]) => {
    let next = 0

    return () => ids[next++] ?? ids[ids.length - 1] ?? ''
  }

  await add('identities.find({ id })', (i) => identities.find({ id: pick(i).id }))
  await add('identities.find({ email })', (i) => identities.find({ email: pick(i).email }))
  await add('identities.find({ sub })', (i) => identities.find({ providerId: 'google', providerSub: pick(i).sub }))
  await add('identities.create', () => identities.create(input()), WRITES)

  const updates = each(await pool())
  await add('identities.update', () => identities.update(updates(), { emailVerified: true }, 1), WRITES)
  const links = await pool()
  const linking = each(links)
  await add('identities.link', () => identities.link(linking(), { addedAt: new Date(), providerId: 'saml', providerSub: `s-${n++}` }), WRITES)
  const unlinking = each(links)
  await add('identities.unlink', () => identities.unlink(unlinking(), 'saml'), WRITES)
  const hidden = await pool()
  const hiding = each(hidden)
  await add('identities.softDelete', () => identities.softDelete(hiding(), 60_000), WRITES)
  const restoring = each(hidden)
  await add('identities.restore', () => identities.restore(restoring()), WRITES)
  const survivors = each(await pool())
  const dups = each(await pool())
  await add('identities.merge', () => identities.merge(survivors(), dups()), WRITES)
  const doomed = each(await pool())
  await add('identities.erase', () => identities.erase(doomed()), WRITES)

  const owner = (await identities.create(input())).id
  const credential = (over: Partial<Credential.UpsertInput> = {}) =>
    credentials.upsert(
      credentialInput({ identityId: owner, kind: 'oauth', secret: `sec-${n++}`, metadata: { provider: 'google', sub: `sub-${n++}` }, ...over }),
      ctx,
    )
  await add('credentials.upsert', () => credential(), WRITES)
  const seeded = await credential()
  await add('credentials.findById', () => credentials.findById(seeded.id, ctx))
  await add('credentials.findByHashedSecret', () => credentials.findByHashedSecret(seeded.secret, 'oauth', ctx))
  await add('credentials.findByProviderSub', () => {
    const meta = seeded.metadata ?? {}

    return credentials.findByProviderSub(String(meta.provider), String(meta.sub), ctx)
  })
  // A holder with what an account really carries, since the pools above pile a thousand rows on `owner`.
  const lister = (await identities.create(input())).id
  for (let i = 0; i < 5; i++) {
    await credentials.upsert(credentialInput({ identityId: lister, kind: 'oauth', secret: `list-${n++}` }), ctx)
  }
  await add('credentials.listByIdentity', () => credentials.listByIdentity(lister, 'oauth', ctx))
  const patched = seeded.id
  await add('credentials.patchMetadata', (i) => credentials.patchMetadata(patched, { seen: i }, ctx), WRITES)
  const rotating: string[] = []
  for (let i = 0; i < WRITES + WARM; i++) rotating.push((await credential()).id)
  const rotatingOne = each(rotating)
  await add('credentials.rotate', () => credentials.rotate(rotatingOne(), `sec-${n++}`, 1, ctx), WRITES)
  const revoking: string[] = []
  for (let i = 0; i < WRITES + WARM; i++) revoking.push((await credential()).id)
  const revokingOne = each(revoking)
  await add('credentials.revoke', () => credentials.revoke(revokingOne(), ctx), WRITES)
  const deleting: string[] = []
  for (let i = 0; i < WRITES + WARM; i++) deleting.push((await credential()).id)
  const deletingOne = each(deleting)
  await add('credentials.delete', () => credentials.delete(deletingOne(), ctx), WRITES)
  const kinds: string[] = []
  for (let i = 0; i < WRITES + WARM; i++) {
    const id = (await identities.create(input())).id
    await credentials.upsert(credentialInput({ identityId: id, kind: 'password', secret: `pw-${n++}` }), ctx)
    kinds.push(id)
  }
  const kindOne = each(kinds)
  await add('credentials.deleteByKind', () => credentials.deleteByKind(kindOne(), 'password', ctx), WRITES)

  const session = () => {
    const at = new Date()
    return sessionInput({
      aal: 1,
      absoluteExpiresAt: new Date(at.getTime() + 604_800_000),
      createdAt: at,
      expiresAt: new Date(at.getTime() + 86_400_000),
      factors: [],
      fresh: true,
      id: (n++).toString(16).padStart(64, '0'),
      identityId: owner,
      kind: 'user',
      rotatedAt: at,
    })
  }
  const opened: string[] = []
  await add('sessions.create', async () => {
    const row = session()
    opened.push(row.id)
    await sessions.create(row)
  }, WRITES)
  await add('sessions.getByHash', () => sessions.getByHash(opened[0] ?? ''))
  await add('sessions.update', () => sessions.update(opened[0] ?? '', { fresh: false }), WRITES)
  for (let i = 0; i < 5; i++) await sessions.create({ ...session(), identityId: lister })
  await add('sessions.listByIdentity', () => sessions.listByIdentity(lister))
  const closing = each(opened)
  await add('sessions.delete', () => sessions.delete(closing()), WRITES)

  // NOTE: the memory adapter keeps no event log, so these two are only measured where there is one.
  if (events) {
    const line = { actorId: null, event: 'signin', identityId: owner, ip: null, metadata: null, method: null, sessionId: null, tenantId: null, userAgent: null }
    await add('events.record', () => events.record(line), WRITES)
    for (let i = 0; i < 5; i++) await events.record({ ...line, identityId: lister })
    await add('events.listByIdentity', () => events.listByIdentity(lister))
  }

  console.log(`\n### ${label}\n\n| call | p50 | p95 |\n| --- | --- | --- |`)
  for (const [name, stat] of out) console.log(`| \`${name}\` | ${fmt(stat.p50)} | ${fmt(stat.p95)} |`)
}

/** A container of our own, on a port of our own, removed on the way out. */
async function container(name: string, args: string[], ready: string[]) {
  try {
    sh('docker', ['rm', '-f', name])
  } catch {}
  sh('docker', ['run', '--rm', '-d', '--name', name, ...args])
  for (let i = 0; i < 90; i++) {
    try {
      sh('docker', ['exec', name, ...ready])
      return
    } catch {
      await wait(1_000)
    }
  }
  throw new Error(`${name} never came up`)
}

const which = process.argv[2] ?? 'all'
const wanted = (backend: string) => which === 'all' || which === backend

if (wanted('memory')) {
  const adapter = new MemoryAdapter()
  const now = new Date()
  for (let i = 1; i <= N; i++) {
    const id = `seed-${i}`
    adapter.raw.identities.set(id, {
      createdAt: now,
      createdBy: null,
      deletedAt: null,
      deletedBy: null,
      emailVerified: true,
      id,
      profile: { email: `user${i}@example.com`, username: `user${i}` },
      providers: [
        { addedAt: now, providerId: 'google', providerSub: `google-${id}` },
        { addedAt: now, providerId: 'github', providerSub: `github-${id}` },
      ],
      updatedAt: now,
      updatedBy: null,
      version: 1,
    })
  }
  await report('Memory', adapter)
}

if (wanted('sqlite')) {
  const file = path.join(os.tmpdir(), `duckauth-bench-${Date.now()}.db`)
  // NOTE: better-sqlite3 is a native addon that takes bun's NAPI bridge down, so under bun this is the
  // driver bun ships. Both are supported clients; the label says which one produced the numbers.
  const onBun = Boolean(process.versions.bun)
  const client = onBun
    ? new (await import('bun:sqlite')).Database(file)
    : new (createRequire(import.meta.url)('better-sqlite3'))(file)
  client.exec(fs.readFileSync(path.join(SCHEMA, 'sqlite-e2e-schema.sql'), 'utf8'))
  client.exec(`
    insert into auth_identities (id, profile, email_verified, version, created_at, updated_at)
    with recursive s(n) as (select 1 union all select n + 1 from s where n < ${N})
    select lower(hex(randomblob(16))), json_object('email', 'user' || n || '@example.com', 'username', 'user' || n),
           1, 1, unixepoch() * 1000, unixepoch() * 1000
    from s;
    insert into auth_identity_providers (id, identity_id, provider_id, provider_sub, added_at)
    select lower(hex(randomblob(16))), i.id, p.pid, p.pid || '-' || i.id, unixepoch() * 1000
    from auth_identities i join (select 'google' as pid union all select 'github') p;
    analyze;
  `)
  const handle = onBun ? (await import('drizzle-orm/bun-sqlite')).drizzle(client) : client
  await report(`SQLite (${onBun ? 'bun:sqlite' : 'better-sqlite3'}, file)`, new DrizzleSqliteAdapter(handle))
  fs.rmSync(file, { force: true })
}

if (wanted('pg')) {
  const name = 'duckauth-bench-pg'
  const psql = ['psql', '-U', 'bench', '-d', 'bench', '-q']
  await container(
    name,
    ['-p', '55433:5432', '-e', 'POSTGRES_PASSWORD=bench', '-e', 'POSTGRES_USER=bench', '-e', 'POSTGRES_DB=bench', 'postgres:18.4-alpine3.24'],
    [...psql, '-c', 'select 1'],
  )
  sh('docker', ['exec', '-i', name, ...psql], fs.readFileSync(path.join(SCHEMA, 'pg-e2e-schema.sql'), 'utf8'))
  sh('docker', ['exec', '-i', name, ...psql], `
    insert into auth_identities (id, profile, email_verified, version, created_at, updated_at)
    select gen_random_uuid(), jsonb_build_object('email', 'user' || g || '@example.com', 'username', 'user' || g), true, 1, now(), now()
    from generate_series(1, ${N}) g;
    insert into auth_identity_providers (id, identity_id, provider_id, provider_sub, added_at)
    select gen_random_uuid(), i.id, p.pid, p.pid || '-' || i.id, now()
    from auth_identities i cross join (values ('google'), ('github')) as p(pid);
    vacuum analyze auth_identities; vacuum analyze auth_identity_providers; checkpoint;
  `)
  await wait(SETTLE_MS)
  await report('Postgres 18.4 (node-postgres, localhost)', new DrizzlePgAdapter('postgres://bench:bench@127.0.0.1:55433/bench'))
  sh('docker', ['rm', '-f', name])
}

if (wanted('mysql')) {
  const name = 'duckauth-bench-my'
  const cli = ['mysql', '-uroot', '-pbench', 'bench']
  await container(name, ['-p', '55434:3306', '-e', 'MYSQL_ROOT_PASSWORD=bench', '-e', 'MYSQL_DATABASE=bench', 'mysql:8'], [
    ...cli,
    '-e',
    'select 1',
  ])
  sh('docker', ['exec', '-i', name, ...cli], fs.readFileSync(path.join(SCHEMA, 'mysql-e2e-schema.sql'), 'utf8'))
  // WARN: no `flush tables` after this. It drops the table cache InnoDB has just warmed and doubles
  // every number that follows, which is the seed's cost being charged to the reads.
  sh('docker', ['exec', '-i', name, ...cli], `
    set session cte_max_recursion_depth = ${N * 2};
    insert into auth_identities (id, profile, email_verified, version)
    with recursive s(n) as (select 1 union all select n + 1 from s where n < ${N})
    select uuid(), json_object('email', concat('user', n, '@example.com'), 'username', concat('user', n)), true, 1 from s;
    insert into auth_identity_providers (id, identity_id, provider_id, provider_sub)
    select uuid(), i.id, p.pid, concat(p.pid, '-', i.id)
    from auth_identities i join (select 'google' as pid union all select 'github') p;
    analyze table auth_identities, auth_identity_providers;
  `)
  await wait(SETTLE_MS)
  await report('MySQL 8 (mysql2, localhost)', new DrizzleMysqlAdapter('mysql://root:bench@127.0.0.1:55434/bench'))
  sh('docker', ['rm', '-f', name])
}

process.exit(0)
