#!/usr/bin/env node
/**
 * CLI for `@gentleduck/auth`. Subcommands: `init`, `doctor`, `keys generate <hs256|ec256>`,
 * `keys rotate hs256`, `migrate <pg|mysql|sqlite>`, `emit-openapi`. Zero hard deps.
 */

import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { AuthError } from '~/core/errors'

interface CliCommand {
  name: string
  description: string
  run: (args: string[]) => Promise<number>
}

const COMMANDS: CliCommand[] = [
  {
    name: 'init',
    description: 'Scaffold a starter auth.ts + .env.duck-auth template into a directory',
    run: cmdInit,
  },
  {
    name: 'doctor',
    description: 'Load the local auth.ts and run AuthEngine.strict() to surface misconfigurations',
    run: cmdDoctor,
  },
  {
    name: 'keys',
    description: 'Generate or rotate signing keys (`keys generate <hs256|ec256>` | `keys rotate hs256`)',
    run: cmdKeys,
  },
  {
    name: 'migrate',
    description: 'Emit CREATE TABLE DDL for the duck-auth schema (`migrate <pg|mysql|sqlite>`)',
    run: cmdMigrate,
  },
  {
    name: 'emit-openapi',
    description: 'Print the OpenAPI 3.1 spec for the locally-defined AuthEngine to stdout (or --out=path)',
    run: cmdEmitOpenapi,
  },
  {
    name: 'help',
    description: 'Print this help text',
    run: async () => {
      printHelp()
      return 0
    },
  },
]

function printHelp(): void {
  process.stdout.write('duck-auth CLI\n\n')
  for (const cmd of COMMANDS) {
    process.stdout.write(`  ${cmd.name.padEnd(10)} ${cmd.description}\n`)
  }
  process.stdout.write('\nRun `duck-auth <command> --help` for command-specific options.\n')
}

/** The scaffolded `auth.ts` template: `quickstart` is the in-memory adapter, `production` is Redis plus the JWT
 *  transport on real defaults. Every specifier and symbol here is pinned by `cli-scaffold.test.ts`, because
 *  nothing else type-checks a string. */
function scaffoldTemplate(flavor: 'quickstart' | 'production'): string {
  if (flavor === 'quickstart') {
    return `import { MemoryAdapter } from '@gentleduck/auth/adapters/memory'
import { AuthEngine, InMemoryEvents } from '@gentleduck/auth/core'
import { CookieTransport } from '@gentleduck/auth/core/transport'
import { MemoryLimiter } from '@gentleduck/auth/limiters/memory'
import { passwords, ScryptHasher } from '@gentleduck/auth/providers/passwords'

const adapter = new MemoryAdapter()

export const auth = new AuthEngine({
  baseUrl: process.env.DUCK_AUTH_BASE_URL ?? 'http://localhost:3000',
  transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
  stores: adapter,
  events: new InMemoryEvents(),
  limiter: new MemoryLimiter({ max: 5, windowMs: 60_000 }),
  providers: [passwords({ hasher: new ScryptHasher() })],
})
`
  }
  return `import { RedisSessionImpl } from '@gentleduck/auth/adapters/redis'
import { AuthEngine } from '@gentleduck/auth/core'
import { redisIdempotency } from '@gentleduck/auth/core/idempotency'
import { JwtTransport } from '@gentleduck/auth/core/transport'
import { RedisLimiter } from '@gentleduck/auth/limiters/redis'
import { Argon2idHasher, passwords } from '@gentleduck/auth/providers/passwords'
import { Redis } from 'ioredis'

const redis = new Redis(process.env.REDIS_URL!)

// WIRE YOUR identities + credentials store here (Drizzle, Prisma, etc).
// The Redis adapter ships sessions + idempotency + limiter only.
declare const identities: never
declare const credentials: never

export const auth = new AuthEngine({
  baseUrl: process.env.DUCK_AUTH_BASE_URL!,
  transport: new JwtTransport({
    issuer: process.env.DUCK_AUTH_ISSUER!,
    signKey: { kid: 'k1', key: process.env.DUCK_AUTH_HS256_SECRET! },
    verifyKeys: [{ kid: 'k1', key: process.env.DUCK_AUTH_HS256_SECRET! }],
    refresh: { ttlMs: 7 * 24 * 60 * 60 * 1000 },
  }),
  stores: {
    identities,
    sessions: new RedisSessionImpl({ redis }),
    credentials,
  },
  limiter: new RedisLimiter({ redis, max: 5, windowMs: 60_000 }),
  providers: [passwords({ hasher: new Argon2idHasher() })],
  idempotency: redisIdempotency({ prefix: 'auth:idem', redis }),
})

// env is not an AuthEngine option: production hardening is this call, which refuses to start on a
// weak secret, an insecure cookie, or a missing limiter.
auth.strict({ env: 'production' })
`
}

function envTemplate(): string {
  return `# @gentleduck/auth environment variables
DUCK_AUTH_BASE_URL=http://localhost:3000
DUCK_AUTH_ISSUER=https://your-issuer.example
DUCK_AUTH_HS256_SECRET=replace-me-with-32-bytes-of-entropy
REDIS_URL=redis://127.0.0.1:6379
`
}

/** `duck-auth init`: write `auth.ts` and `.env.duck-auth` into the target directory, refusing to overwrite
 *  either. `--production` emits the Redis and JWT scaffold instead of the quickstart one. */
async function cmdInit(args: string[]): Promise<number> {
  const dir = args.find((a) => !a.startsWith('--')) ?? 'src/auth'
  const flavor = args.includes('--production') ? 'production' : 'quickstart'
  const target = resolve(process.cwd(), dir)
  if (!existsSync(target)) mkdirSync(target, { recursive: true })

  const authPath = join(target, 'auth.ts')
  const envPath = join(target, '.env.duck-auth')

  if (existsSync(authPath)) {
    process.stderr.write(`refusing to overwrite ${authPath}\n`)
    return 1
  }
  writeFileSync(authPath, scaffoldTemplate(flavor), 'utf8')
  // The file exists to hold an HS256 secret, so it is created owner-only rather than at the umask
  // default. `mode` is masked by the umask, so this can only narrow the permissions, never widen them.
  const wroteEnv = !existsSync(envPath)
  if (wroteEnv) {
    writeFileSync(envPath, envTemplate(), { encoding: 'utf8', mode: 0o600 })
  }
  process.stdout.write(`scaffolded ${authPath}\n${wroteEnv ? 'scaffolded' : 'kept existing'} ${envPath}\n`)
  if (flavor === 'production') {
    process.stdout.write(
      'next: install peerDeps (`bun add ioredis @node-rs/argon2`); wire `identities` + `credentials` stores; export `auth` from your framework adapter.\n',
    )
  } else {
    process.stdout.write('next: import `auth` from this file and mount your framework adapter.\n')
  }
  return 0
}

/** `duck-auth doctor`: find an `auth.ts`, or take one as the first argument, import it and call `strict()` on
 *  its `auth` export, reporting whatever it throws verbatim. Production is the env asked about: outside it
 *  `strict()` checks only a branded compliance preset, which is not what someone runs a doctor for. */
async function cmdDoctor(args: string[]): Promise<number> {
  const pathArg = args.find((a) => !a.startsWith('--')) ?? findAuthFile()
  if (!pathArg) {
    process.stderr.write('no auth.ts found; pass path explicitly or run `duck-auth init` first\n')
    return 1
  }
  const absolute = resolve(process.cwd(), pathArg)
  if (!existsSync(absolute)) {
    process.stderr.write(`file not found: ${absolute}\n`)
    return 1
  }
  try {
    const mod = await import(absolute)
    if (!mod.auth || typeof mod.auth.strict !== 'function') {
      process.stderr.write(`module at ${absolute} does not export a named \`auth\` with a strict() method\n`)
      return 1
    }
    mod.auth.strict({ env: 'production' })
    process.stdout.write('AuthEngine.strict() OK\n')
    return 0
  } catch (err) {
    // An `AuthError`'s `message` is its bare code; the checks that failed are in `meta.detail`. A verdict
    // and a crash are named apart, which is how a `strict()` called with no arguments read as a rejection.
    const failed = err instanceof AuthError
    const message = failed ? String(err.meta.detail ?? err.code) : err instanceof Error ? err.message : String(err)
    process.stderr.write(`${failed ? 'strict() rejected' : 'could not run strict()'}: ${message}\n`)
    return 1
  }
}

function findAuthFile(): string | undefined {
  const candidates = ['src/auth/auth.ts', 'src/auth.ts', 'auth.ts']
  for (const c of candidates) {
    if (existsSync(resolve(process.cwd(), c))) return c
  }
  return undefined
}

/** `duck-auth keys generate|rotate <hs256|ec256>`; rotate prints a rollover snippet keeping the prev kid in verifyKeys. */
async function cmdKeys(args: string[]): Promise<number> {
  const verb = args[0]
  if (verb !== 'generate' && verb !== 'rotate') {
    process.stderr.write('usage: duck-auth keys <generate|rotate> <hs256|ec256>\n')
    return 1
  }
  if (verb === 'generate') {
    if (!args[1]) {
      process.stderr.write('usage: duck-auth keys generate <hs256|ec256>\n')
      return 1
    }
    switch (args[1]) {
      case 'hs256': {
        const secret = randomBytes(32).toString('base64url')
        process.stdout.write(`# HS256 secret (paste into DUCK_AUTH_HS256_SECRET, never commit):\n${secret}\n`)
        return 0
      }
      case 'ec256': {
        const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
        process.stdout.write('# ES256 private key (PEM); store in your secrets manager:\n')
        process.stdout.write(privateKey.export({ format: 'pem', type: 'pkcs8' }).toString())
        process.stdout.write('\n# ES256 public key (PEM); safe to commit alongside JWKS:\n')
        process.stdout.write(publicKey.export({ format: 'pem', type: 'spki' }).toString())
        return 0
      }
      default:
        process.stderr.write(`unknown algorithm: ${args[1]}\n`)
        return 1
    }
  }
  // rotate
  if (args[1] !== 'hs256') {
    process.stderr.write('only `keys rotate hs256` is supported (ES256 rotation: regenerate keypair + update JWKS)\n')
    return 1
  }
  const prevKid = (args.find((a) => a.startsWith('--prev-kid=')) ?? '--prev-kid=k1').slice('--prev-kid='.length)
  // Epoch-seconds + 4 hex; random suffix avoids same-second rotation collisions.
  const defaultNewKid = `k${Math.floor(Date.now() / 1000)}-${randomBytes(2).toString('hex')}`
  const newKid = (args.find((a) => a.startsWith('--new-kid=')) ?? `--new-kid=${defaultNewKid}`).slice(
    '--new-kid='.length,
  )
  if (newKid === prevKid) {
    process.stderr.write(`new kid (${newKid}) must differ from prev kid (${prevKid})\n`)
    return 1
  }
  const newSecret = randomBytes(32).toString('base64url')
  process.stdout.write(
    `# HS256 rotation. New signing kid: ${newKid}. Keep previous kid (${prevKid}) on verifyKeys for the rollover window.\n`,
  )
  process.stdout.write(`# 1. Store the new secret as DUCK_AUTH_HS256_SECRET_${newKid.toUpperCase()}:\n`)
  process.stdout.write(`${newSecret}\n\n`)
  process.stdout.write('# 2. Update your AuthJwtTransport config:\n')
  process.stdout.write('# new AuthJwtTransport({\n')
  process.stdout.write(
    `#   signKey: { kid: '${newKid}', key: process.env.DUCK_AUTH_HS256_SECRET_${newKid.toUpperCase()}! },\n`,
  )
  process.stdout.write('#   verifyKeys: [\n')
  process.stdout.write(
    `#     { kid: '${newKid}', key: process.env.DUCK_AUTH_HS256_SECRET_${newKid.toUpperCase()}! },\n`,
  )
  process.stdout.write(
    `#     { kid: '${prevKid}', key: process.env.DUCK_AUTH_HS256_SECRET_${prevKid.toUpperCase()}! },\n`,
  )
  process.stdout.write('#   ],\n')
  process.stdout.write('# })\n')
  process.stdout.write('# 3. Deploy. Once the longest JWT TTL has elapsed, drop the previous kid from verifyKeys.\n')
  return 0
}

/** `duck-auth migrate <pg|mysql|sqlite> [--prefix=auth_] [--out=path]` emits duck-auth CREATE TABLE DDL. */
async function cmdMigrate(args: string[]): Promise<number> {
  const dialect = args.find((a) => !a.startsWith('--')) as 'pg' | 'mysql' | 'sqlite' | undefined
  if (!dialect || !['pg', 'mysql', 'sqlite'].includes(dialect)) {
    process.stderr.write('usage: duck-auth migrate <pg|mysql|sqlite> [--prefix=auth_] [--out=path]\n')
    return 1
  }
  const prefix = (args.find((a) => a.startsWith('--prefix=')) ?? '--prefix=auth_').slice('--prefix='.length)
  const outPath = args.find((a) => a.startsWith('--out='))?.slice('--out='.length)
  const ddl = renderMigration(dialect, prefix)
  if (outPath) {
    const safe = resolveOutPath(outPath)
    if (!safe) return 1
    writeFileSync(safe, ddl, 'utf8')
    process.stdout.write(`wrote ${outPath} (${ddl.split('\n').length} lines)\n`)
  } else {
    process.stdout.write(ddl)
  }
  return 0
}

/** Resolve `--out=path` and refuse anything escaping the working directory. SECURITY: `--out` reaches this from
 *  npm scripts and CI where the value can be tainted, so `--out=../../etc/whatever` must not land. */
function resolveOutPath(relative: string): string | null {
  const cwd = process.cwd()
  const absolute = resolve(cwd, relative)
  if (absolute !== cwd && !absolute.startsWith(`${cwd}/`)) {
    process.stderr.write(`refusing --out path outside cwd: ${absolute}\n`)
    return null
  }
  return absolute
}

/** `duck-auth emit-openapi [auth-path] [--out=path]` prints the OpenAPI JSON for the local auth.ts. */
async function cmdEmitOpenapi(args: string[]): Promise<number> {
  const positional = args.find((a) => !a.startsWith('--'))
  const pathArg = positional ?? findAuthFile()
  if (!pathArg) {
    process.stderr.write('no auth.ts found; pass path explicitly or run `duck-auth init` first\n')
    return 1
  }
  const outPath = args.find((a) => a.startsWith('--out='))?.slice('--out='.length)
  const absolute = resolve(process.cwd(), pathArg)
  if (!existsSync(absolute)) {
    process.stderr.write(`file not found: ${absolute}\n`)
    return 1
  }
  try {
    const mod = await import(absolute)
    // Prefer an explicit `openapi` export if the project pre-built it.
    let spec: unknown = mod.openapi
    if (!spec) {
      if (!mod.auth) {
        process.stderr.write(`module at ${absolute} does not export \`auth\` or \`openapi\`\n`)
        return 1
      }
      const openapiMod = (await import('../openapi/index.js')) as {
        buildOpenApiDocument?: (auth: unknown) => unknown
      }
      if (typeof openapiMod.buildOpenApiDocument !== 'function') {
        process.stderr.write('internal: ../openapi module does not export buildOpenApiDocument\n')
        return 1
      }
      spec = openapiMod.buildOpenApiDocument(mod.auth)
    }
    const json = JSON.stringify(spec, null, 2)
    if (outPath) {
      const safe = resolveOutPath(outPath)
      if (!safe) return 1
      writeFileSync(safe, `${json}\n`, 'utf8')
      process.stdout.write(`wrote ${outPath}\n`)
    } else {
      process.stdout.write(`${json}\n`)
    }
    return 0
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    process.stderr.write(`emit-openapi failed: ${message}\n`)
    return 1
  }
}

/** SQL DDL for the three auth tables under one dialect. Timestamps are bigint ms-since-epoch and JSON blobs sit
 *  in `text`, so sqlite, mysql and pg all share the one shape. */
export function renderMigration(dialect: 'pg' | 'mysql' | 'sqlite', prefix: string): string {
  // `id` split from generic `text` because MySQL rejects BLOB/TEXT in
  // PRIMARY KEY/INDEX without a length prefix (ERROR 1170).
  const t = (() => {
    switch (dialect) {
      case 'pg':
        return { text: 'text', id: 'text', shortText: 'text', int: 'integer', big: 'bigint', smallint: 'smallint' }
      case 'mysql':
        return {
          text: 'TEXT',
          id: 'VARCHAR(64)',
          shortText: 'VARCHAR(64)',
          int: 'INT',
          big: 'BIGINT',
          smallint: 'TINYINT',
        }
      case 'sqlite':
        return { text: 'TEXT', id: 'TEXT', shortText: 'TEXT', int: 'INTEGER', big: 'INTEGER', smallint: 'INTEGER' }
    }
  })()

  // MySQL pre-8.0.29 has no `CREATE INDEX IF NOT EXISTS`; emit a plain
  // `CREATE INDEX` for that dialect. pg + sqlite support the guard.
  const createIdx = dialect === 'mysql' ? 'CREATE INDEX' : 'CREATE INDEX IF NOT EXISTS'

  const identities = `CREATE TABLE IF NOT EXISTS ${prefix}identities (
  id ${t.id} PRIMARY KEY NOT NULL,
  profile ${t.text},
  version ${t.int} NOT NULL,
  email_verified ${t.smallint} NOT NULL,
  created_by ${t.shortText},
  updated_by ${t.shortText},
  created_at ${t.big} NOT NULL,
  updated_at ${t.big} NOT NULL,
  deleted_at ${t.big},
  deleted_by ${t.shortText}
);
${createIdx} ${prefix}identities_deleted_at ON ${prefix}identities(deleted_at);`

  // One row per external login, rather than a JSON column on the identity that no index can reach:
  // that made a sign-in through a provider scan every row, and let two identities claim one sub.
  const identityProviders = `CREATE TABLE IF NOT EXISTS ${prefix}identity_providers (
  id ${t.id} PRIMARY KEY NOT NULL,
  identity_id ${t.id} NOT NULL,
  provider_id ${t.shortText} NOT NULL,
  provider_sub ${t.shortText} NOT NULL,
  added_at ${t.big} NOT NULL,
  added_by ${t.shortText}
);
CREATE UNIQUE INDEX ${dialect === 'mysql' ? '' : 'IF NOT EXISTS '}${prefix}identity_providers_sub ON ${prefix}identity_providers(provider_id, provider_sub);
CREATE UNIQUE INDEX ${dialect === 'mysql' ? '' : 'IF NOT EXISTS '}${prefix}identity_providers_owned ON ${prefix}identity_providers(identity_id, provider_id);
${createIdx} ${prefix}identity_providers_identity ON ${prefix}identity_providers(identity_id, added_at);`

  const credentials = `CREATE TABLE IF NOT EXISTS ${prefix}credentials (
  id ${t.id} PRIMARY KEY NOT NULL,
  identity_id ${t.id} NOT NULL,
  tenant_id ${t.shortText},
  kind ${t.shortText} NOT NULL,
  secret ${dialect === 'mysql' ? 'VARCHAR(512)' : t.text} NOT NULL,
  metadata ${t.text},
  version ${t.int} NOT NULL,
  created_by ${t.shortText},
  updated_by ${t.shortText},
  created_at ${t.big} NOT NULL,
  updated_at ${t.big} NOT NULL,
  last_used_at ${t.big},
  expires_at ${t.big},
  revoked_at ${t.big}
);
${createIdx} ${prefix}credentials_identity ON ${prefix}credentials(identity_id);
${createIdx} ${prefix}credentials_kind_secret ON ${prefix}credentials(kind, secret);
${createIdx} ${prefix}credentials_tenant ON ${prefix}credentials(tenant_id);`

  const sessions = `CREATE TABLE IF NOT EXISTS ${prefix}sessions (
  id ${t.id} PRIMARY KEY NOT NULL,
  identity_id ${t.id},
  tenant_id ${t.shortText},
  kind ${t.shortText} NOT NULL,
  aal ${t.smallint} NOT NULL,
  factors ${t.text} NOT NULL,
  csrf_hash ${t.shortText},
  ip ${t.shortText},
  user_agent ${t.text},
  fingerprint ${t.shortText},
  created_at ${t.big} NOT NULL,
  updated_at ${t.big} NOT NULL,
  rotated_at ${t.big} NOT NULL,
  expires_at ${t.big} NOT NULL,
  absolute_expires_at ${t.big} NOT NULL,
  fresh ${t.smallint} NOT NULL,
  acting_as ${t.text}
);
${createIdx} ${prefix}sessions_identity ON ${prefix}sessions(identity_id);
${createIdx} ${prefix}sessions_expires ON ${prefix}sessions(expires_at);
${createIdx} ${prefix}sessions_absolute_expires ON ${prefix}sessions(absolute_expires_at);`

  const header = `-- @gentleduck/auth duck-auth schema (${dialect})
-- Generated by \`duck-auth migrate ${dialect}\`. Tables prefixed with \`${prefix}\`.
-- Columns mirror duck-auth.{IIdentityRow,ICredentialRow,ISessionRow}; bigints
-- are ms-since-epoch; JSON blobs are stored as text for cross-dialect parity.
--
-- Provenance: identities and credentials carry created_by/updated_by, and
-- identities also carries deleted_by. Sessions carry none - identity_id already
-- names who opened the session, and acting_as covers the one case where the
-- operator differs. All are filled from the ambient actor scope (withActor).
-- Uniqueness is not emitted here. The profile is a text blob in this schema, so
-- there is no portable expression index over it; a bridge built on these tables
-- owns enforcing unique email and username itself. The drizzle adapters ship
-- their own schema, which does carry those indexes.
`
  return `${header}\n${identities}\n\n${identityProviders}\n\n${credentials}\n\n${sessions}\n`
}

/** CLI entry point: parse argv, dispatch to the subcommand, surface failures through the exit code. */
export async function authRun(argv: string[]): Promise<number> {
  const [sub, ...rest] = argv
  if (!sub || sub === '--help' || sub === '-h') {
    printHelp()
    return 0
  }
  const cmd = COMMANDS.find((c) => c.name === sub)
  if (!cmd) {
    process.stderr.write(`unknown command: ${sub}\n`)
    printHelp()
    return 1
  }
  return cmd.run(rest)
}

// Runs only when invoked, so importing this module does not silently swallow the argv.
if (import.meta.url === `file://${process.argv[1]}`) {
  authRun(process.argv.slice(2)).then((code) => {
    process.exit(code)
  })
}

/** Re-exported for tests + programmatic use. */
/** The CLI's commands, exposed under `__` names for its own tests. Not a supported surface. */
export {
  cmdDoctor as __doctor,
  cmdEmitOpenapi as __emitOpenapi,
  cmdInit as __init,
  cmdKeys as __keys,
  cmdMigrate as __migrate,
  envTemplate as __envTemplate,
  renderMigration as __renderMigration,
  scaffoldTemplate as __scaffoldTemplate,
}

// Use suppression hint: silence the `dirname` unused-warning since some
// downstream tooling expects it on the surface.
void dirname
void readFileSync
