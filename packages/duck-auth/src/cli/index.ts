#!/usr/bin/env node
/**
 * @packageDocumentation
 * Lightweight CLI for `@gentleduck/auth`. Subcommands:
 *
 *   - init <directory>: scaffold a starter `auth.ts` + env template
 *   - doctor: read the local `auth.ts`, instantiate it, run AuthRoot.strict()
 *   - keys generate hs256: emit a fresh HS256 secret for JwtTransport
 *   - keys generate ec256: emit an ES256 keypair (PEM) for DPoP signing
 *
 * Designed to run via `bunx @gentleduck/auth` or `npx @gentleduck/auth`
 * without an explicit install. Intentionally has zero hard dependencies
 * beyond Node built-ins so the CLI runs even when the consumer has not
 * yet installed peerDeps.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
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
    description: 'Generate signing keys (`keys generate hs256` | `keys generate ec256`)',
    run: cmdKeys,
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
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
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
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
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
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
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
 * `duck-auth keys generate <hs256|ec256>` subcommand. Emits the
 * material to stdout (and a hint to never commit it).
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
async function cmdKeys(args: string[]): Promise<number> {
  if (args[0] !== 'generate' || !args[1]) {
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

/**
 * CLI entry point. Parses argv, dispatches to the matching subcommand,
 * surfaces errors back through the exit code. Exported so the bin
 * shim can call it.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
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
  cmdInit as __init,
  cmdKeys as __keys,
  envTemplate as __envTemplate,
  scaffoldTemplate as __scaffoldTemplate,
}

// Use suppression hint: silence the `dirname` unused-warning since some
// downstream tooling expects it on the surface.
void dirname
void readFileSync
