#!/usr/bin/env node
/**
 * Lightweight CLI for `@gentleduck/auth`. Subcommands:
 *
 *   - init <directory>: scaffold a starter `auth.ts` + env template
 *   - doctor: read the local `auth.ts`, instantiate it, run AuthRoot.strict()
 *   - keys generate hs256: emit a fresh HS256 secret for JwtTransport
 *   - keys generate ec256: emit an ES256 keypair (PEM) for DPoP signing
 *   - keys rotate hs256: emit a NEW HS256 secret + rollover snippet
 *   - migrate <pg|mysql|sqlite>: emit CREATE TABLE DDL for the SqlBridge schema
 *   - emit-openapi: import local auth.ts and print the OpenAPI 3.1 spec
 *
 * Designed to run via `bunx @gentleduck/auth` or `npx @gentleduck/auth`
 * without an explicit install. Intentionally has zero hard dependencies
 * beyond Node built-ins so the CLI runs even when the consumer has not
 * yet installed peerDeps.
 */

import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'

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
    description: 'Load the local auth.ts and run AuthRoot.strict() to surface misconfigurations',
    run: cmdDoctor,
  },
  {
    name: 'keys',
    description: 'Generate or rotate signing keys (`keys generate <hs256|ec256>` | `keys rotate hs256`)',
    run: cmdKeys,
  },
  {
    name: 'migrate',
    description: 'Emit CREATE TABLE DDL for the SqlBridge schema (`migrate <pg|mysql|sqlite>`)',
    run: cmdMigrate,
  },
  {
    name: 'emit-openapi',
    description: 'Print the OpenAPI 3.1 spec for the locally-defined AuthRoot to stdout (or --out=path)',
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

/**
 * Resolve the path to the scaffolded auth.ts template. Two flavors:
 *   - quickstart: in-memory adapter, suitable for hello-world
 *   - production: Redis + JWT transport, real defaults
 */
function scaffoldTemplate(flavor: 'quickstart' | 'production'): string {
  if (flavor === 'quickstart') {
    return `import { AuthRoot, InMemoryEvents, ScryptHasher } from '@gentleduck/auth/core'
import { MemoryAuthAdapter } from '@gentleduck/auth/adapters/memory'
import { MemoryLimiter } from '@gentleduck/auth/limiters/memory'
import { CookieTransport } from '@gentleduck/auth/core/transport'

const adapter = new MemoryAuthAdapter()

export const auth = new AuthRoot({
  baseUrl: process.env.DUCK_AUTH_BASE_URL ?? 'http://localhost:3000',
  transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
  stores: {
    identities: adapter.identities,
    sessions: adapter.sessions,
    credentials: adapter.credentials,
  },
  events: new InMemoryEvents(),
  limiter: new MemoryLimiter({ max: 5, windowMs: 60_000 }),
  passwords: { hasher: new ScryptHasher() },
})
`
  }
  return `import { AuthRoot, Argon2idHasher } from '@gentleduck/auth/core'
import { JwtTransport } from '@gentleduck/auth/core/transport'
import { RedisIdempotencyStore, RedisLimiter, RedisSessionStore } from '@gentleduck/auth/adapters/redis'
import { Redis } from 'ioredis'

const redis = new Redis(process.env.REDIS_URL!)

// WIRE YOUR identities + credentials store here (Drizzle, Prisma, etc).
// The Redis adapter ships sessions + idempotency + limiter only.
declare const identities: never
declare const credentials: never

export const auth = new AuthRoot({
  baseUrl: process.env.DUCK_AUTH_BASE_URL!,
  transport: new JwtTransport({
    issuer: process.env.DUCK_AUTH_ISSUER!,
    signKey: { kid: 'k1', key: process.env.DUCK_AUTH_HS256_SECRET! },
    verifyKeys: [{ kid: 'k1', key: process.env.DUCK_AUTH_HS256_SECRET! }],
    refresh: { ttlMs: 7 * 24 * 60 * 60 * 1000 },
  }),
  stores: {
    identities,
    sessions: new RedisSessionStore({ redis }),
    credentials,
  },
  limiter: new RedisLimiter({ redis, max: 5, windowMs: 60_000 }),
  passwords: { hasher: new Argon2idHasher() },
  idempotency: { store: new RedisIdempotencyStore({ redis }), ttlMs: 24 * 60 * 60 * 1000 },
  env: 'production',
})
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

/**
 * `duck-auth init` subcommand. Writes `auth.ts` + `.env.duck-auth` into
 * the target directory; refuses to overwrite existing files.
 *
 * Flags:
 *   --production: emit the production-grade scaffold (Redis + JWT)
 */
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
  if (!existsSync(envPath)) {
    writeFileSync(envPath, envTemplate(), 'utf8')
  }
  process.stdout.write(`scaffolded ${authPath}\nscaffolded ${envPath}\n`)
  if (flavor === 'production') {
    process.stdout.write(
      'next: install peerDeps (`bun add ioredis @node-rs/argon2`); wire `identities` + `credentials` stores; export `auth` from your framework adapter.\n',
    )
  } else {
    process.stdout.write('next: import `auth` from this file and mount your framework adapter.\n')
  }
  return 0
}

/**
 * `duck-auth doctor` subcommand. Looks for an `auth.ts` (or path passed
 * as the first arg), dynamic-imports it, and calls `auth.strict()` on
 * the default export named `auth`. Reports any thrown error verbatim.
 */
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
    const mod = (await import(absolute)) as { auth?: { strict?: () => void } }
    if (!mod.auth || typeof mod.auth.strict !== 'function') {
      process.stderr.write(`module at ${absolute} does not export a named \`auth\` with a strict() method\n`)
      return 1
    }
    mod.auth.strict()
    process.stdout.write('AuthRoot.strict() OK\n')
    return 0
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    process.stderr.write(`strict() rejected: ${message}\n`)
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

/**
 * `duck-auth keys generate <hs256|ec256>` subcommand. Emits fresh signing
 * material to stdout.
 *
 * `duck-auth keys rotate hs256` emits a NEW signing key plus a JwtTransport
 * config snippet that keeps the previous key in `verifyKeys` so in-flight
 * JWTs validate during the rollover window. Caller supplies the previous
 * kid via `--prev-kid=<kid>` (default `k1`) and the new kid via
 * `--new-kid=<kid>` (default `k$(epoch)`).
 */
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
  process.stdout.write('# 2. Update your JwtTransport config:\n')
  process.stdout.write('# new JwtTransport({\n')
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

/**
 * `duck-auth migrate <pg|mysql|sqlite>` subcommand. Emits the CREATE TABLE
 * DDL matching the row shapes declared in `SqlBridge.{IIdentityRow,
 * ICredentialRow, ISessionRow}` so consumers can run it via psql /
 * mysql / sqlite without hand-translating from the types file.
 *
 * Flags:
 *   --prefix=<name>  Table-name prefix (default `auth_`).
 *   --out=<path>     Write to a file instead of stdout.
 */
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

/**
 * Resolve `--out=path` to an absolute path and refuse anything that
 * escapes the current working directory. `--out` shows up in npm
 * scripts and CI pipelines where the input can be tainted; constraining
 * to cwd prevents `--out=../../etc/whatever` from clobbering files
 * outside the repo.
 */
function resolveOutPath(relative: string): string | null {
  const cwd = process.cwd()
  const absolute = resolve(cwd, relative)
  if (absolute !== cwd && !absolute.startsWith(`${cwd}/`)) {
    process.stderr.write(`refusing --out path outside cwd: ${absolute}\n`)
    return null
  }
  return absolute
}

/**
 * `duck-auth emit-openapi` subcommand. Dynamic-imports the local
 * `auth.ts`, looks for an exported `openapi` builder or instantiates
 * `buildOpenApiDocument(auth)`, and prints the JSON spec.
 *
 * Flags:
 *   --out=<path>  Write to a file instead of stdout.
 *   <auth-path>   Override default auth.ts lookup.
 */
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
    const mod = (await import(absolute)) as {
      auth?: unknown
      openapi?: unknown
    }
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

/**
 * Build the SQL DDL for the three auth tables under the chosen dialect.
 * Bigints are used for ms-since-epoch columns; JSON-encoded blobs sit
 * as `text` for portability (no jsonb / json column types so sqlite +
 * mysql + pg all share the same shape).
 */
function renderMigration(dialect: 'pg' | 'mysql' | 'sqlite', prefix: string): string {
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
  tenant_id ${t.shortText},
  profile ${t.text},
  providers ${t.text} NOT NULL,
  version ${t.int} NOT NULL,
  created_at ${t.big} NOT NULL,
  updated_at ${t.big} NOT NULL,
  deleted_at ${t.big}
);
${createIdx} ${prefix}identities_tenant ON ${prefix}identities(tenant_id);
${createIdx} ${prefix}identities_deleted_at ON ${prefix}identities(deleted_at);`

  const credentials = `CREATE TABLE IF NOT EXISTS ${prefix}credentials (
  id ${t.id} PRIMARY KEY NOT NULL,
  identity_id ${t.id} NOT NULL,
  tenant_id ${t.shortText},
  kind ${t.shortText} NOT NULL,
  secret ${dialect === 'mysql' ? 'VARCHAR(512)' : t.text} NOT NULL,
  metadata ${t.text},
  version ${t.int} NOT NULL,
  created_at ${t.big} NOT NULL,
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
  rotated_at ${t.big} NOT NULL,
  expires_at ${t.big} NOT NULL,
  absolute_expires_at ${t.big} NOT NULL,
  fresh ${t.smallint} NOT NULL,
  acting_as ${t.text}
);
${createIdx} ${prefix}sessions_identity ON ${prefix}sessions(identity_id);
${createIdx} ${prefix}sessions_expires ON ${prefix}sessions(expires_at);
${createIdx} ${prefix}sessions_absolute_expires ON ${prefix}sessions(absolute_expires_at);`

  const header = `-- @gentleduck/auth SqlBridge schema (${dialect})
-- Generated by \`duck-auth migrate ${dialect}\`. Tables prefixed with \`${prefix}\`.
-- Columns mirror SqlBridge.{IIdentityRow,ICredentialRow,ISessionRow}; bigints
-- are ms-since-epoch; JSON blobs are stored as text for cross-dialect parity.
`
  return `${header}\n${identities}\n\n${credentials}\n\n${sessions}\n`
}

/**
 * CLI entry point. Parses argv, dispatches to the matching subcommand,
 * surfaces errors back through the exit code. Exported so the bin
 * shim can call it.
 */
export async function run(argv: string[]): Promise<number> {
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

// Avoid silent eats when imported by another module - run only when invoked.
if (import.meta.url === `file://${process.argv[1]}`) {
  run(process.argv.slice(2)).then((code) => {
    process.exit(code)
  })
}

/** Re-exported for tests + programmatic use. */
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
